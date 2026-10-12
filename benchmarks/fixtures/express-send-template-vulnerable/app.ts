export function handler(req: any, res: any) {
  const markup = `<h1>Results for ${req.query.term}</h1>`;
  return res.send(markup);
}
