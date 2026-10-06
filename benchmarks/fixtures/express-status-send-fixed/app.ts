export function handler(req: any, res: any) {
  return res.status(200).json({ term: req.query.term });
}
