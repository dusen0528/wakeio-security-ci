export function handler(req: any, response: any) {
  return response.send('<p>' + req.query.message + '</p>');
}
