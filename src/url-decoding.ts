import { parse as parseHtml } from "parse5";

const META_PRESCAN_BYTES = 1024;
const MAX_CHARSET_LENGTH = 64;

interface CharsetDeclaration {
  label: string;
  malformed?: boolean;
}

interface MetaNode {
  tagName?: string;
  attrs?: Array<{ name: string; value: string }>;
  childNodes?: MetaNode[];
}

export interface DecodedUrlText {
  text: string;
  /** Fixed, redacted notes; each note means decoding coverage is incomplete. */
  notes: string[];
}

function charsetParameter(value: string): CharsetDeclaration | undefined {
  const parameters = value.split(";").slice(1);
  const declarations = parameters.filter((part) => /^\s*charset(?:\s|=|$)/i.test(part));
  if (declarations.length === 0) return undefined;
  const match = /^\s*charset\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"']+))\s*$/i.exec(declarations[0]);
  return { label: match?.[1] ?? match?.[2] ?? match?.[3] ?? "", malformed: !match || declarations.length > 1 };
}

function metaCharset(body: Uint8Array): CharsetDeclaration | undefined {
  // Parse only the early byte prefix, using one character per byte. This
  // avoids interpreting meta-shaped strings in HTML comments or scripts and
  // never walks template content or follows references from the prescan.
  const prefix = Buffer.from(body.subarray(0, META_PRESCAN_BYTES)).toString("latin1");
  const document = parseHtml(prefix) as unknown as MetaNode;
  const pending: MetaNode[] = [document];
  while (pending.length > 0) {
    const node = pending.pop()!;
    if (node.tagName === "meta") {
      const attr = (name: string) => node.attrs?.find((entry) => entry.name === name)?.value;
      const charset = attr("charset");
      if (charset !== undefined) return { label: charset };
      if (attr("http-equiv")?.trim().toLowerCase() === "content-type") {
        const declaration = charsetParameter(attr("content") ?? "");
        if (declaration) return declaration;
      }
    }
    for (let index = (node.childNodes?.length ?? 0) - 1; index >= 0; index -= 1) pending.push(node.childNodes![index]);
  }
  return undefined;
}

/** Decode collected bytes only; this helper never fetches or guesses encodings. */
export function decodeUrlText(body: Uint8Array, contentType: string | undefined, kind: "html" | "text" | "module"): DecodedUrlText {
  const notes: string[] = [];
  let declaration: CharsetDeclaration | undefined;
  let declaredByMeta = false;
  // Module responses are always UTF-8, regardless of transport charset or a
  // UTF-16 BOM. Invalid UTF-8 still produces the ordinary partial note below.
  // https://html.spec.whatwg.org/multipage/webappapis.html#fetch-a-single-module-script
  if (kind === "module" || (body[0] === 0xef && body[1] === 0xbb && body[2] === 0xbf)) declaration = { label: "utf-8" };
  // Explicitly recognize unsupported UTF-32 BOMs rather than mistaking the
  // little-endian BOM for UTF-16 and silently inspecting corrupted text.
  else if ((body[0] === 0xff && body[1] === 0xfe && body[2] === 0 && body[3] === 0)
    || (body[0] === 0 && body[1] === 0 && body[2] === 0xfe && body[3] === 0xff)) declaration = { label: "utf-32" };
  else if (body[0] === 0xff && body[1] === 0xfe) declaration = { label: "utf-16le" };
  else if (body[0] === 0xfe && body[1] === 0xff) declaration = { label: "utf-16be" };
  else {
    declaration = charsetParameter(contentType ?? "");
    if (!declaration && kind === "html") {
      try { declaration = metaCharset(body); declaredByMeta = declaration !== undefined; }
      catch { notes.push("The bounded HTML encoding prescan failed; text coverage may be incomplete."); }
    }
  }

  let label = declaration?.label.trim() ?? "utf-8";
  let decoder: TextDecoder;
  try {
    if (declaration?.malformed || !label || label.length > MAX_CHARSET_LENGTH) throw new RangeError("invalid charset");
    decoder = new TextDecoder(label, { fatal: true });
    // HTML's encoding prescan maps UTF-16 meta declarations (including
    // aliases) to UTF-8. BOM and HTTP declarations keep their own precedence.
    // https://html.spec.whatwg.org/multipage/parsing.html#prescan-a-byte-stream-to-determine-its-encoding
    if (declaredByMeta && (decoder.encoding === "utf-16le" || decoder.encoding === "utf-16be")) {
      label = "utf-8";
      decoder = new TextDecoder(label, { fatal: true });
    }
  } catch {
    notes.push("An unsupported or malformed character encoding was declared; UTF-8 fallback text coverage may be incomplete.");
    label = "utf-8";
    decoder = new TextDecoder(label, { fatal: true });
  }
  try { return { text: decoder.decode(body), notes }; }
  catch {
    notes.push("Malformed byte sequences were replaced while decoding collected text; text coverage may be incomplete.");
    return { text: new TextDecoder(label, { fatal: false }).decode(body), notes };
  }
}
