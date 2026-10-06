export function GET(request: any) {
  const term = request.nextUrl.searchParams.get('term');
  return Response.json({ term });
}
