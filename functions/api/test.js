export async function onRequest(context) {
  return new Response("Hello World", {
    headers: {
      "Content-Type": "text/plain;charset=UTF-8",
      "Access-Control-Allow-Origin": "*"
    }
  });
} 