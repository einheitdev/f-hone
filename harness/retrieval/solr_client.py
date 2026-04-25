"""Thin Solr REST wrapper.

Uses requests directly — pysolr is overkill and pulls extra deps.
The HTTP surface we need is tiny: select, update (atomic), delete.

Default URL: http://localhost:8983/solr/hone (matches the docker
compose setup at docker/docker-compose.yml).
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Iterable
from urllib import error, parse, request
import json


_DEFAULT_URL = "http://localhost:8983/solr/hone"


class SolrError(RuntimeError):
  """Raised on any non-2xx Solr response."""


@dataclass(frozen=True)
class SolrClient:
  """Connection to one Solr core."""
  base_url: str = _DEFAULT_URL
  timeout: float = 10.0

  def ping(self) -> bool:
    """Return True iff the core responds to /admin/ping."""
    try:
      self._get("admin/ping")
      return True
    except (SolrError, error.URLError):
      return False

  def upsert(self, doc: dict, commit: bool = True) -> None:
    """Insert or update one document by id."""
    self.upsert_many([doc], commit=commit)

  def upsert_many(self, docs: Iterable[dict], commit: bool = True) -> None:
    """Batch upsert (atomic per doc; Solr dedups on `id`)."""
    body = list(docs)
    if not body:
      return
    params = {"commit": "true" if commit else "false"}
    self._post("update", json.dumps(body).encode("utf-8"), params=params)

  def delete_by_query(self, q: str, commit: bool = True) -> None:
    """Delete every doc matching `q`. Use `*:*` to wipe the core."""
    payload = json.dumps({"delete": {"query": q}}).encode("utf-8")
    params = {"commit": "true" if commit else "false"}
    self._post("update", payload, params=params)

  def search(
    self,
    q: str = "*:*",
    fq: list[str] | None = None,
    rows: int = 10,
    sort: str | None = None,
    fl: str | None = None,
  ) -> list[dict]:
    """Run a select query, return parsed docs."""
    params: dict[str, Any] = {"q": q, "rows": str(rows), "wt": "json"}
    if fq:
      params["fq"] = fq  # repeated param OK in Solr
    if sort:
      params["sort"] = sort
    if fl:
      params["fl"] = fl
    resp = self._get("select", params=params)
    return resp.get("response", {}).get("docs", [])

  # --- HTTP plumbing ---

  def _url(self, endpoint: str) -> str:
    """Build absolute URL: base + /endpoint."""
    return f"{self.base_url.rstrip('/')}/{endpoint.lstrip('/')}"

  def _get(self, endpoint: str, params: dict | None = None) -> dict:
    """GET that returns parsed JSON."""
    url = self._url(endpoint)
    if params:
      query = parse.urlencode(params, doseq=True)
      url = f"{url}?{query}"
    req = request.Request(url, method="GET")
    return self._exec(req)

  def _post(
    self,
    endpoint: str,
    body: bytes,
    params: dict | None = None,
  ) -> dict:
    """POST JSON body, return parsed JSON response."""
    url = self._url(endpoint)
    if params:
      query = parse.urlencode(params, doseq=True)
      url = f"{url}?{query}"
    req = request.Request(
      url, method="POST", data=body,
      headers={"Content-Type": "application/json"},
    )
    return self._exec(req)

  def _exec(self, req: request.Request) -> dict:
    try:
      with request.urlopen(req, timeout=self.timeout) as resp:
        if resp.status >= 400:
          raise SolrError(
            f"{req.full_url}: HTTP {resp.status}"
          )
        return json.loads(resp.read().decode("utf-8"))
    except error.HTTPError as exc:
      body = exc.read().decode("utf-8", "replace")
      raise SolrError(f"{req.full_url}: HTTP {exc.code} {body}") from exc
