from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def read_root():
    return {"test1": "test1"}
