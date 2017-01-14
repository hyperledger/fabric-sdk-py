import tarfile


def create_targz(src, dst):
    """ Create a .tar.gz file to dst with given content from src
    Args:
        src: source content
        dst: destination tar.gz file path

    Returns: Bool
    """
    try:
        with tarfile.open(dst, mode='w:gz') as out:
            out.add(src)
    except Exception as e:
        raise e
    return True
