# security.py

import ast
import re
from typing import Any


# ============================================================
# DANGEROUS IMPORTS
# ============================================================

DANGEROUS_IMPORTS = {
    "os",
    "subprocess",
    "socket",
    "requests",
    "urllib",
    "urllib3",
    "http",
    "httpx",
    "shutil",
    "ftplib",
    "telnetlib",
}


# ============================================================
# DANGEROUS FUNCTIONS
# ============================================================

DANGEROUS_FUNCTIONS = {
    "eval",
    "exec",
    "compile",
    "__import__",
    "open",
}


# ============================================================
# DANGEROUS ATTRIBUTES
# ============================================================

DANGEROUS_ATTRIBUTES = {
    # Filesystem read
    "scandir",
    "listdir",
    "walk",
    "listdir",
    "readlink",

    # Filesystem write
    "remove",
    "unlink",
    "rmdir",
    "makedirs",
    "mkdir",
    "rename",
    "replace",
    "chmod",
    "chown",

    # Environment
    "getenv",
    "environ",

    # Process
    "system",
    "popen",
}


# ============================================================
# CAPABILITY RISK
# ============================================================

CAPABILITY_RISK = {
    "filesystem_read": 60,
    "filesystem_write": 80,
    "network": 60,
    "process_execution": 100,
    "dynamic_execution": 100,
}


# ============================================================
# PROMPT PATTERNS
#
# These detect what the USER is asking for.
#
# This is important because the LLM might refuse to generate
# dangerous code. Empty code does NOT mean the request is safe.
# ============================================================

PROMPT_PATTERNS = {

    # --------------------------------------------------------
    # FILESYSTEM READ
    # --------------------------------------------------------

    "filesystem_read": [

        r"/etc/passwd",
        r"/etc/shadow",
        r"/etc/hosts",
        r"/proc/",
        r"/sys/",

        r"\bread\b.*\bfile\b",
        r"\bread\b.*\bfilesystem\b",
        r"\bread\b.*\bsystem\s+file\b",

        r"\baccess\b.*\bfile\b",
        r"\baccess\b.*\bfilesystem\b",

        r"\blist\b.*\bdirector",
        r"\bscan\b.*\bdirector",
        r"\bwalk\b.*\bdirector",

        r"\bfind\b.*\bfiles\b",
        r"\bget\b.*\bfile\b",
    ],


    # --------------------------------------------------------
    # FILESYSTEM WRITE
    # --------------------------------------------------------

    "filesystem_write": [

        r"\bwrite\b.*\bfile\b",
        r"\bmodify\b.*\bfile\b",
        r"\bchange\b.*\bfile\b",

        r"\bcreate\b.*\bfile\b",

        r"\bdelete\b.*\bfile\b",
        r"\bremove\b.*\bfile\b",

        r"\bdelete\b.*\bdirector",
        r"\bremove\b.*\bdirector",

        r"\brename\b.*\bfile\b",
        r"\boverwrite\b.*\bfile\b",
    ],


    # --------------------------------------------------------
    # NETWORK
    # --------------------------------------------------------

    "network": [

        r"\bconnect\b.*\bnetwork\b",
        r"\bconnect\b.*\binternet\b",
        r"\bnetwork\s+connection\b",

        r"\bsend\b.*\bover\s+the\s+network\b",
        r"\bsend\b.*\bto\b.*\bserver\b",

        r"\bdownload\b.*\bfrom\b",
        r"\bupload\b.*\bto\b",

        r"\brequest\b.*\bwebsite\b",
        r"\brequest\b.*\burl\b",

        r"\bconnect\b.*\bserver\b",

        r"\bhttp://",
        r"\bhttps://",

        r"\bexternal\s+api\b",
        r"\bapi\s+request\b",
    ],


    # --------------------------------------------------------
    # PROCESS EXECUTION
    # --------------------------------------------------------

    "process_execution": [

        r"\bexecute\b.*\bprocess\b",
        r"\bexecute\b.*\bcommand\b",

        r"\brun\b.*\bcommand\b",
        r"\brun\b.*\bshell\b",

        r"\bspawn\b.*\bprocess\b",
        r"\blaunch\b.*\bprocess\b",

        r"\bshell\s+command\b",
        r"\bcommand\s+line\b",

        r"\bterminal\s+command\b",
    ],


    # --------------------------------------------------------
    # DYNAMIC EXECUTION
    # --------------------------------------------------------

    "dynamic_execution": [

        r"\bdynamically\b.*\bexecute\b.*\bcode\b",
        r"\bdynamic\s+code\b",

        r"\bexecute\b.*\bcode\b.*\bruntime\b",

        r"\beval\b",
        r"\bexec\b",

        r"\bexecute\s+user\s+input\b",
        r"\brun\s+user\s+supplied\s+code\b",
    ],
}


# ============================================================
# ENVIRONMENT ACCESS
# ============================================================

ENVIRONMENT_PATTERNS = [
    r"\benvironment\s+variables\b",
    r"\benv\s+variables\b",
    r"\bgetenv\b",
    r"\bos\.environ\b",
    r"\bread\b.*\benvironment\b",
]


# ============================================================
# ANALYZE USER PROMPT
# ============================================================

def analyze_prompt(prompt: str) -> dict[str, Any]:
    """
    Analyze the original user request.

    This is separate from code analysis because an LLM can
    refuse to generate dangerous code.

    Example:

        prompt = "Read /etc/passwd"

        code = ""

    The request is still dangerous.
    """

    findings: list[str] = []
    capabilities: set[str] = set()

    if not prompt:
        return {
            "findings": [],
            "capabilities": [],
        }

    prompt_lower = prompt.lower()

    # --------------------------------------------------------
    # Capability pattern matching
    # --------------------------------------------------------

    for capability, patterns in PROMPT_PATTERNS.items():

        for pattern in patterns:

            try:
                matched = re.search(
                    pattern,
                    prompt_lower,
                    flags=re.IGNORECASE,
                )

            except re.error:
                matched = False

            if matched:

                capabilities.add(capability)

                findings.append(
                    f"User request indicates "
                    f"{capability.replace('_', ' ')}"
                )

                break

    # --------------------------------------------------------
    # Environment access
    # --------------------------------------------------------

    for pattern in ENVIRONMENT_PATTERNS:

        if re.search(
            pattern,
            prompt_lower,
            flags=re.IGNORECASE,
        ):

            capabilities.add("filesystem_read")

            findings.append(
                "User request indicates environment access"
            )

            break

    return {
        "findings": findings,
        "capabilities": sorted(capabilities),
    }


# ============================================================
# GET ATTRIBUTE CHAIN
#
# Example:
#
# os.system()
#
# becomes:
#
# os.system
# ============================================================

def get_attribute_chain(node: ast.AST) -> str:

    parts = []

    current = node

    while isinstance(current, ast.Attribute):

        parts.append(current.attr)

        current = current.value

    if isinstance(current, ast.Name):

        parts.append(current.id)

    return ".".join(reversed(parts))


# ============================================================
# ANALYZE PYTHON CODE
# ============================================================

def analyze_code(code: str) -> dict[str, Any]:
    """
    Analyze generated Python code using AST.

    IMPORTANT:

    Empty code is not considered dangerous by itself.

    Prompt analysis happens separately in analyze_prompt().
    """

    findings: list[str] = []
    capabilities: set[str] = set()

    # --------------------------------------------------------
    # Empty code
    # --------------------------------------------------------

    if not code or not code.strip():

        return {
            "findings": [],
            "capabilities": [],
        }

    # --------------------------------------------------------
    # Parse Python
    # --------------------------------------------------------

    try:

        tree = ast.parse(code)

    except SyntaxError as e:

        return {
            "findings": [
                f"Invalid Python syntax: {e}"
            ],

            "capabilities": [
                "unknown"
            ],

            "invalid": True,
        }

    # --------------------------------------------------------
    # Walk AST
    # --------------------------------------------------------

    for node in ast.walk(tree):

        # ====================================================
        # IMPORT
        # ====================================================

        if isinstance(node, ast.Import):

            for alias in node.names:

                module = alias.name.split(".")[0]

                if module in DANGEROUS_IMPORTS:

                    findings.append(
                        f"Dangerous import detected: {module}"
                    )

                    # Filesystem
                    if module in {
                        "os",
                        "shutil",
                    }:

                        capabilities.add(
                            "filesystem_read"
                        )

                    # Network
                    elif module in {
                        "requests",
                        "urllib",
                        "urllib3",
                        "http",
                        "httpx",
                        "socket",
                        "ftplib",
                        "telnetlib",
                    }:

                        capabilities.add(
                            "network"
                        )

                    # Process
                    elif module == "subprocess":

                        capabilities.add(
                            "process_execution"
                        )


        # ====================================================
        # FROM IMPORT
        # ====================================================

        elif isinstance(node, ast.ImportFrom):

            if node.module:

                module = node.module.split(".")[0]

                if module in DANGEROUS_IMPORTS:

                    findings.append(
                        f"Dangerous import detected: {module}"
                    )

                    if module in {
                        "os",
                        "shutil",
                    }:

                        capabilities.add(
                            "filesystem_read"
                        )

                    elif module in {
                        "requests",
                        "urllib",
                        "urllib3",
                        "http",
                        "httpx",
                        "socket",
                        "ftplib",
                        "telnetlib",
                    }:

                        capabilities.add(
                            "network"
                        )

                    elif module == "subprocess":

                        capabilities.add(
                            "process_execution"
                        )


        # ====================================================
        # FUNCTION CALL
        # ====================================================

        elif isinstance(node, ast.Call):

            if isinstance(node.func, ast.Name):

                function_name = node.func.id

                if function_name in DANGEROUS_FUNCTIONS:

                    findings.append(
                        f"Dangerous function detected: "
                        f"{function_name}"
                    )

                    if function_name == "open":

                        capabilities.add(
                            "filesystem_read"
                        )

                    elif function_name in {
                        "eval",
                        "exec",
                        "compile",
                        "__import__",
                    }:

                        capabilities.add(
                            "dynamic_execution"
                        )


            # ----------------------------------------------
            # Attribute function calls
            # ----------------------------------------------

            elif isinstance(node.func, ast.Attribute):

                attribute = node.func.attr

                chain = get_attribute_chain(
                    node.func
                )

                if attribute in DANGEROUS_ATTRIBUTES:

                    findings.append(
                        f"Dangerous filesystem operation "
                        f"detected: {chain}"
                    )

                    if attribute in {
                        "scandir",
                        "listdir",
                        "walk",
                        "readlink",
                    }:

                        capabilities.add(
                            "filesystem_read"
                        )

                    elif attribute in {
                        "remove",
                        "unlink",
                        "rmdir",
                        "makedirs",
                        "mkdir",
                        "rename",
                        "replace",
                        "chmod",
                        "chown",
                    }:

                        capabilities.add(
                            "filesystem_write"
                        )

                # ------------------------------------------
                # Environment
                # ------------------------------------------

                if attribute == "getenv":

                    findings.append(
                        "Environment variable access detected"
                    )

                    capabilities.add(
                        "filesystem_read"
                    )

                # ------------------------------------------
                # Process execution
                # ------------------------------------------

                if attribute in {
                    "system",
                    "popen",
                }:

                    findings.append(
                        f"Process execution detected: {chain}"
                    )

                    capabilities.add(
                        "process_execution"
                    )


        # ====================================================
        # os.environ
        # ====================================================

        elif isinstance(node, ast.Attribute):

            chain = get_attribute_chain(node)

            if chain.endswith("os.environ"):

                findings.append(
                    "Environment variable access detected"
                )

                capabilities.add(
                    "filesystem_read"
                )

    return {
        "findings": findings,
        "capabilities": sorted(capabilities),
    }


# ============================================================
# CALCULATE RISK
# ============================================================

def calculate_risk(
    capabilities: set[str],
) -> int:

    if not capabilities:

        return 0

    return max(
        CAPABILITY_RISK.get(
            capability,
            100,
        )

        for capability in capabilities
    )


# ============================================================
# FINAL REQUEST ANALYSIS
# ============================================================

def analyze_request(
    prompt: str,
    code: str,
) -> dict[str, Any]:
    """
    Analyze BOTH:

        1. Original user request
        2. Generated Python code

    The two results are combined.

    This prevents an LLM refusal from accidentally turning
    a dangerous request into an ALLOW decision.
    """

    # --------------------------------------------------------
    # Prompt analysis
    # --------------------------------------------------------

    prompt_result = analyze_prompt(prompt)

    # --------------------------------------------------------
    # Code analysis
    # --------------------------------------------------------

    code_result = analyze_code(code)

    # --------------------------------------------------------
    # Combine capabilities
    # --------------------------------------------------------

    capabilities = set(
        prompt_result["capabilities"]
    )

    capabilities.update(
        code_result["capabilities"]
    )

    # --------------------------------------------------------
    # Combine findings
    # --------------------------------------------------------

    findings = (
        prompt_result["findings"]
        + code_result["findings"]
    )

    # --------------------------------------------------------
    # Handle invalid code
    # --------------------------------------------------------

    if code_result.get("invalid"):

        capabilities.add("unknown")

        findings.append(
            "Generated code could not be safely analyzed"
        )

    # --------------------------------------------------------
    # Risk
    # --------------------------------------------------------

    risk_score = calculate_risk(
        capabilities
    )

    # --------------------------------------------------------
    # Safety
    # --------------------------------------------------------

    safe = (
        risk_score < 50
        and "unknown" not in capabilities
    )

    return {
        "safe": safe,
        "risk_score": risk_score,
        "findings": findings,
        "capabilities": sorted(capabilities),
    }


# ============================================================
# POLICY GENERATOR
# ============================================================

def generate_policy(
    security_result: dict[str, Any],
) -> dict[str, Any]:
    """
    Convert security analysis into a restrictive policy.

    DENY by default for dangerous capabilities.
    """

    capabilities = set(
        security_result.get(
            "capabilities",
            [],
        )
    )

    # --------------------------------------------------------
    # Decision
    # --------------------------------------------------------

    if not security_result.get("safe", False):

        decision = "DENY"

    else:

        decision = "ALLOW"

    # --------------------------------------------------------
    # Policy
    # --------------------------------------------------------

    return {

        "decision": decision,

        "network": (
            "network" in capabilities
            and decision == "ALLOW"
        ),

        "filesystem_read": (
            "filesystem_read" in capabilities
            and decision == "ALLOW"
        ),

        "filesystem_write": (
            "filesystem_write" in capabilities
            and decision == "ALLOW"
        ),

        "process_execution": (
            "process_execution" in capabilities
            and decision == "ALLOW"
        ),

        "dynamic_execution": (
            "dynamic_execution" in capabilities
            and decision == "ALLOW"
        ),
    }


# ============================================================
# COMPLETE SECURITY PIPELINE
# ============================================================

def security_pipeline(
    prompt: str,
    code: str,
) -> dict[str, Any]:
    """
    One function for your FastAPI backend.

    Usage:

        result = security_pipeline(
            prompt=user_prompt,
            code=generated_code,
        )
    """

    security = analyze_request(
        prompt=prompt,
        code=code,
    )

    policy = generate_policy(
        security
    )

    return {
        "security": security,
        "policy": policy,
    }