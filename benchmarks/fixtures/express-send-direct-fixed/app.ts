export function handler(req: { query: { message: string } }, res: any) {
  return res.json({ message: req.query.message });
}
