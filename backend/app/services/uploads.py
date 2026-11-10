class PathRejected(ValueError):
    pass


def owned_storage_path(user_id: str, storage_path: str) -> str:
    path = storage_path.strip()
    prefix = f"{user_id}/"
    remainder = path[len(prefix) :] if path.startswith(prefix) else ""
    if (
        not remainder
        or remainder.startswith("/")
        or path.endswith("/")
        or ".." in path
        or "\\" in path
        or path.startswith("/")
    ):
        raise PathRejected("Storage path is not valid")
    return path
