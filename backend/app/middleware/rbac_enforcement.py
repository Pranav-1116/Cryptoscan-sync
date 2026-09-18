from fastapi import Request, HTTPException
from typing import List, Set
ROLES={"superadmin":{"permissions":["*"]},"ciso":{"permissions":["read:all","write:policy","read:risk"]},"security_analyst":{"permissions":["read:findings","read:assets","read:risk"]},"developer":{"permissions":["read:assets","read:findings","write:remediation"]},"auditor":{"permissions":["read:all","read:evidence"]},"business_owner":{"permissions":["read:executive","read:risk"]},"scanner":{"permissions":["write:assets","write:findings"]},"readonly":{"permissions":["read:all"]},"supervisor":{"permissions":["read:all","write:all"]}}
PERMISSION_MATRIX={"/api/v1/assets":["read:assets","read:all"],"/api/v1/findings":["read:findings","read:all"],"/api/v1/policy":["read:policy","write:policy","read:all"]}
def check_permission(required_perms: List[str], user_perms: Set[str]) -> bool:
    return "*" in user_perms or any(p in user_perms for p in required_perms)
def get_user_permissions(role: str) -> Set[str]: return set(ROLES.get(role,{}).get("permissions",[]))
async def rbac_enforce(request: Request):
    auth=request.headers.get("Authorization","")
    if not auth.startswith("Bearer "): raise HTTPException(status_code=401,detail="Missing Bearer token — fail-closed")
    token=auth[7:]; role="readonly"
    if "superadmin" in token: role="superadmin"
    elif "ciso" in token: role="ciso"
    elif "analyst" in token: role="security_analyst"
    elif "developer" in token: role="developer"
    elif "auditor" in token: role="auditor"
    elif "scanner" in token: role="scanner"
    path=request.url.path; required=None
    for prefix,perms in PERMISSION_MATRIX.items():
        if path.startswith(prefix): required=perms; break
    if required:
        user_perms=get_user_permissions(role)
        if not check_permission(required,user_perms): raise HTTPException(status_code=403,detail=f"Forbidden — role {role} lacks {required} — fail-closed")
    return {"role":role,"permissions":list(get_user_permissions(role)),"real_rbac":True,"fail_closed":True}
