from app.agents.base_agent import BaseAgent
from app.memory.vault import create_memory
from app.memory.retrieval import retrieve_memories

class MemoryAgent(BaseAgent):
    def __init__(self):
        super().__init__("MemoryAgent")

    def store_memory(self, db, user_id: str, fact: str) -> dict:
        self.log(f"Persisting memory to SQL and Vector DB: {fact[:50]}...")
        return create_memory(db=db, user_id=user_id, fact=fact)

    def retrieve_context(self, db, user_id: str, query: str) -> dict:
        self.log(f"Retrieving context for query: {query[:50]}...")
        return retrieve_memories(db=db, user_id=user_id, query=query)
