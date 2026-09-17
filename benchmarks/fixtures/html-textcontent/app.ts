export function render(req: any, node: any) {
  node.textContent = req.query.html;
}
