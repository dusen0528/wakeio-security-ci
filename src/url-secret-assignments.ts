/** Only the matched span and its offset are needed by the redacted reporter. */
export interface SecretAssignmentMatch {
  0: string;
  index: number;
}

/**
 * Consume candidate names before classifying them. An unanchored repeated
 * prefix retries every suffix of long `word-word-...` input, even when there
 * are no findings to cap. Here the name pass always advances over each token,
 * and the classifier is anchored with unambiguous alphanumeric/separator
 * segments. Whitespace is consumed once per delimiter, without overlapping
 * optional whitespace groups that can backtrack on an absent assignment.
 */
export function* scanSecretAssignments(text: string): Generator<SecretAssignmentMatch> {
  const names = /\b[A-Za-z0-9]+(?:[_-][A-Za-z0-9]+)*/g;
  const secretName = /^(?:[A-Za-z0-9]+[_-])*(?:api[_-]?key|secret(?:[_-]?key)?|service[_-]?role(?:[_-]?key)?|access[_-]?(?:key|token)|auth(?:orization)?|password|passwd|private[_-]?key|client[_-]?secret|session[_-]?token)$/i;
  const whitespace = /\s*/y;
  const literal = /"[^"\r\n]{8,}"|'[^'\r\n]{8,}'|[A-Za-z0-9+/_=-]{16,}/y;
  const skipWhitespace = (offset: number): number => {
    whitespace.lastIndex = offset;
    whitespace.exec(text);
    return whitespace.lastIndex;
  };
  for (let name = names.exec(text); name; name = names.exec(text)) {
    const nameEnd = names.lastIndex;
    // A trailing underscore is a word character, so it fails the original
    // key's word-boundary requirement (a trailing hyphen fails below).
    if (text[nameEnd] === "_" || !secretName.test(name[0])) continue;
    let cursor = skipWhitespace(nameEnd);
    if (text[cursor] === '"' || text[cursor] === "'") cursor = skipWhitespace(cursor + 1);
    if (text[cursor] !== ":" && text[cursor] !== "=") continue;
    literal.lastIndex = skipWhitespace(cursor + 1);
    const value = literal.exec(text);
    if (!value) continue;
    // Match the old global scan's non-overlapping spans, including its
    // literal-only values and quoted JSON/object property handling.
    names.lastIndex = literal.lastIndex;
    yield { 0: text.slice(name.index, literal.lastIndex), index: name.index };
  }
}
