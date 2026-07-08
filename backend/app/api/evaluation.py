from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.evaluation.metrics import compute_classification_metrics
from app.learning.classification_tracker import get_learning_stats
from app.research.poisoning_dataset import POISONING_DATASET

router = APIRouter(prefix="/evaluation", tags=["Evaluation"])


@router.get("/metrics")
def get_metrics(db: Session = Depends(get_db)):
    return compute_classification_metrics(db)


@router.get("/learning")
def get_learning(db: Session = Depends(get_db)):
    return get_learning_stats(db)


@router.get("/poisoning-dataset")
def get_poisoning_dataset():
    return {
        "categories": list(POISONING_DATASET.keys()),
        "total_examples": sum(len(v) for v in POISONING_DATASET.values()),
        "dataset": POISONING_DATASET,
    }
@router.get("/research-metrics")
def get_research_metrics(
    db: Session = Depends(get_db)
):
    return compute_classification_metrics(db)


@router.get("/model-benchmarks")
def get_model_benchmarks():
    import os
    import pandas as pd
    from fastapi import HTTPException
    
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    metrics_path = os.path.join(base_dir, "reports", "metrics_table.csv")
    
    if not os.path.exists(metrics_path):
        raise HTTPException(status_code=404, detail="Benchmark metrics table not found. Run benchmark_models.py first.")
        
    try:
        df = pd.read_csv(metrics_path)
        # Convert to dictionary (list of records)
        records = df.to_dict(orient="records")
        return records
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load metrics: {str(e)}")