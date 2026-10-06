export function GET(request: any) {
  const term = request.nextUrl.searchParams.get('term');
  return new Response(`<h1>${term}</h1>`, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}
