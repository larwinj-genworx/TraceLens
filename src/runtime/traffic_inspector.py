from __future__ import annotations

from urllib.parse import urlparse

import httpx

from src.schemas.internal import RuntimeProbe, ServiceMatch


class TrafficInspector:
    async def capture(
        self,
        matches: list[ServiceMatch],
        runtime_ports: dict[str, int],
        timeout_seconds: int = 10,
    ) -> list[RuntimeProbe]:
        probes: list[RuntimeProbe] = []
        seen_requests: set[tuple[str, str]] = set()

        async with httpx.AsyncClient(timeout=timeout_seconds, follow_redirects=True) as client:
            for service, host_port in runtime_ports.items():
                health_url = f"http://localhost:{host_port}/health"
                probes.append(await self._probe(client, service, "GET", health_url, None, {}))

            for match in matches:
                method = match.call.method.upper()
                url = self._resolve_runtime_url(match, runtime_ports)
                key = (method, url)
                if key in seen_requests:
                    continue
                seen_requests.add(key)

                payload = self._build_payload(match.call.payload_fields)
                probes.append(
                    await self._probe(
                        client=client,
                        service=match.backend_repo,
                        method=method,
                        url=url,
                        payload=payload,
                        headers=match.call.headers,
                    )
                )

        return probes

    async def _probe(
        self,
        client: httpx.AsyncClient,
        service: str,
        method: str,
        url: str,
        payload: dict | None,
        headers: dict[str, str],
    ) -> RuntimeProbe:
        request_headers = dict(headers)
        request_headers.setdefault("x-tracelens-probe", "true")

        try:
            if method in {"GET", "DELETE", "HEAD", "OPTIONS"}:
                response = await client.request(method, url, headers=request_headers)
            else:
                response = await client.request(method, url, headers=request_headers, json=payload or {})

            return RuntimeProbe(
                service=service,
                method=method,
                url=url,
                status_code=response.status_code,
                request_headers=request_headers,
                response_headers=dict(response.headers),
                response_body_snippet=response.text[:800],
            )
        except Exception as exc:  # noqa: BLE001
            return RuntimeProbe(
                service=service,
                method=method,
                url=url,
                request_headers=request_headers,
                error=str(exc),
            )

    def _resolve_runtime_url(self, match: ServiceMatch, runtime_ports: dict[str, int]) -> str:
        port = runtime_ports.get(match.backend_repo, 8000)
        resolved = match.call.resolved_url or match.call.raw_url

        if resolved.startswith("http://") or resolved.startswith("https://"):
            parsed = urlparse(resolved)
            path = parsed.path or "/"
            query = f"?{parsed.query}" if parsed.query else ""
            return f"http://localhost:{port}{path}{query}"

        path = resolved if resolved.startswith("/") else match.endpoint.path
        return f"http://localhost:{port}{path}"

    def _build_payload(self, payload_fields: dict[str, str]) -> dict:
        payload: dict[str, object] = {}
        for key, value_type in payload_fields.items():
            lowered = value_type.lower()
            if lowered == "string":
                payload[key] = "sample"
            elif lowered == "number":
                payload[key] = 1
            elif lowered == "boolean":
                payload[key] = True
            elif lowered == "array":
                payload[key] = ["sample"]
            elif lowered == "object":
                payload[key] = {"sample": "value"}
            elif lowered == "null":
                payload[key] = None
            else:
                payload[key] = "sample"
        return payload
