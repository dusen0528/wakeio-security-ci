export function handler(req: { query: { message: string } }, res: any) {
  return res.send(req.query.message);
}
