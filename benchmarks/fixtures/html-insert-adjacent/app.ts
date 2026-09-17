export function render(req: any, node: any) {
  node.insertAdjacentHTML("beforeend", req.query.html);
}
