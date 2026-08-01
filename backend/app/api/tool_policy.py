from fastapi import APIRouter

from app.memory_security.detectors.tool_policy_validator import (
    ToolPolicyValidator,
    detect_tool_policy_poisoning
)

from app.memory_security.tool_policy_config import (
    APPROVED_DOMAINS,
    APPROVED_APIS,
    TRUSTED_TOOLS,
    ALLOWED_BEHAVIORS,
)

router = APIRouter(
    prefix="/tool-policy",
    tags=["Tool Policy"]
)


@router.post("/validate")
def validate_policy(text: str):

    return detect_tool_policy_poisoning(text)


@router.get("/approved-domains")
def approved_domains():

    return {
        "approved_domains": sorted(
            APPROVED_DOMAINS
        )
    }


@router.get("/approved-apis")
def approved_apis():

    return {
        "approved_apis": sorted(
            APPROVED_APIS
        )
    }


@router.get("/trusted-tools")
def trusted_tools():

    return {
        "trusted_tools": sorted(
            TRUSTED_TOOLS
        )
    }


@router.get("/allowed-behaviors")
def allowed_behaviors():

    return {
        "allowed_behaviors": sorted(
            ALLOWED_BEHAVIORS
        )
    }


@router.post("/compare")
def compare_policies(
    old_policy: str,
    new_policy: str
):

    return ToolPolicyValidator.compare_tool_policies(
        old_policy,
        new_policy
    )


from fastapi import Depends
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.memory_security.services.tool_policy_event_logger import log_tool_policy_event

@router.post("/execute")
def execute_tool(
    tool_name: str,
    parameters: dict,
    user_id: str = "default_user",
    original_user_prompt: str = None,
    db: Session = Depends(get_db)
):
    result = ToolPolicyValidator.validate_tool_execution(
        db=db,
        tool_name=tool_name,
        parameters=parameters,
        user_id=user_id,
        original_user_prompt=original_user_prompt
    )

    if result["decision"] == "BLOCK":
        log_tool_policy_event(
            db=db,
            user_id=user_id,
            policy_text=f"Execution of tool {tool_name} with params {parameters}",
            violation_reason=result["violation_reason"],
            risk_score=result["risk_score"],
            decision="BLOCK",
            unapproved_domains=",".join(result["unapproved_domains"])
        )

    return result

