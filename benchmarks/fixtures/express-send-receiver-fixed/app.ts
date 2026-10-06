const counter = { send(message: string) { return message.length; } };
export function handler(req: any) {
  return counter.send(req.query.message);
}
