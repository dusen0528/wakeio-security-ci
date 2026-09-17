export function render(req: any, node: any) {
  const outer = req.query.html;
  function safe(req: any) {
    node.innerHTML = "<p>fixed</p>";
    return req.query.html;
  }
  return safe(req) || outer;
}
