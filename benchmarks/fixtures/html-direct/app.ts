export function render(req: any, node: any) {
  node.innerHTML = req.query.html;
}
