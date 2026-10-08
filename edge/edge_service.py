"""Edge node: fast, local processing of each chunk. Keeps no data.

Run from the repo root:  python -m edge.edge_service
"""

import logging

from fastapi import FastAPI

from shared.api_models import ProcessIn
from shared.config import EDGE_PORT, SERVICE_HOST
from shared.processing import assess_comfort
from shared.service_utils import install_malformed_handler, log_event, run_service

HOP = "fork-edge"

log = logging.getLogger("edge")
app = FastAPI(title="IoT edge node")
install_malformed_handler(app, log, HOP)


@app.post("/process")
async def process(incoming: ProcessIn):
    chunk_id = str(incoming.chunk_id)
    result = assess_comfort(incoming.data.model_dump())
    log_event(log, logging.INFO, "processed", HOP, chunk_id=chunk_id, result=result)
    return {"chunk_id": chunk_id, "result": result}


if __name__ == "__main__":
    run_service(app, SERVICE_HOST, EDGE_PORT,
                banner=f"Edge listening on {SERVICE_HOST}:{EDGE_PORT}")
