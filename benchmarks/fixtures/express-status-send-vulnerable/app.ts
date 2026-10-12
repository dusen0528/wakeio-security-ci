export function handler(req: any, res: any) {
  return res.status(200).send('<h1>' + req.query.term + '</h1>');
}
