export function render(req: any) {
  const markup = req.query.html;
  document.body.innerHTML = markup;
}
