import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine

from server.api import router
from server.db import BatchJob, ScanJob, get_session


@pytest.fixture()
def client():
    engine = create_engine("sqlite:///:memory:")
    SQLModel.metadata.create_all(engine)

    def override_get_session():
        with Session(engine) as session:
            yield session

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_session] = override_get_session

    with TestClient(app) as test_client:
        yield test_client, engine

    app.dependency_overrides.clear()


def test_submit_batch_creates_batch_and_child_jobs(client):
    test_client, engine = client

    response = test_client.post(
        "/admin/batch",
        json={"urls": ["https://one.test", "https://two.test"]},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "queued"
    assert payload["batch_id"]

    with Session(engine) as session:
        batch = session.get(BatchJob, payload["batch_id"])
        assert batch is not None
        assert batch.status == "queued"

        jobs = session.query(ScanJob).all()
        assert len(jobs) == 2
        assert {job.url for job in jobs} == {"https://one.test", "https://two.test"}
        assert {job.batch_id for job in jobs} == {payload["batch_id"]}
