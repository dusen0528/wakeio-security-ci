export function render(node: any) {
  const example = "node.innerHTML = req.query.html";
  node.innerHTML = "<p>fixed</p>";
  return example;
}
