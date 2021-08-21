# https://jira.hyperledger.org/browse/FAB-7065
# ?page=com.atlassian.jira.plugin.system.issuetabpanels%3Acomment
# -tabpanel&showAll=true
import io
import json
import logging
import os
import tarfile
import time

from hfc.util.consts import CC_TYPE_GOLANG, CC_TYPE_NODE

_logger = logging.getLogger(__name__)


def zeroTarInfo(tarinfo):
    tarinfo.uid = tarinfo.gid = 500
    tarinfo.mode = 100644
    tarinfo.mtime = 0
    tarinfo.pax_headers = {
        'atime': 0,
        'ctime': 0,
    }
    return tarinfo


# http://www.onicos.com/staff/iz/formats/gzip.html
# https://github.com/python/cpython/blob/master/Lib/tarfile.py#L420
class zeroTimeContextManager(object):
    def __enter__(self):
        self.real_time = time.time
        time.time = lambda: 0

    def __exit__(self, type, value, traceback):
        time.time = self.real_time


def _tar_path(proj_path, go_path=None):
    """Tar the project path

    :param proj_path: The full path to the code
    :return: The tar stream.
    """

    if not os.listdir(proj_path):
        raise ValueError("No chaincode file found!")

    tar_stream = io.BytesIO()
    with zeroTimeContextManager():
        dist = tarfile.open(fileobj=tar_stream,
                            mode='w|gz', format=tarfile.GNU_FORMAT)
        for dir_path, _, file_names in os.walk(proj_path):
            for filename in file_names:

                file_path = os.path.join(dir_path, filename)

                with open(file_path, mode='rb') as f:
                    if go_path:
                        arcname = os.path.relpath(file_path, go_path)
                    else:
                        arcname = os.path.relpath(file_path)
                    tarinfo = dist.gettarinfo(file_path, arcname)
                    tarinfo = zeroTarInfo(tarinfo)
                    dist.addfile(tarinfo, f)

        dist.close()
        tar_stream.seek(0)
        return tar_stream.read()


def package_chaincode(cc_path, cc_type=CC_TYPE_GOLANG):
    """Package all chaincode env into a tar.gz file
    This creates archive with only source, equivalent to core.tar.gz in 2.0 lifecycle

    :param cc_path: path to the chaincode
    :param cc_type: chaincode type (Default value = CC_TYPE_GOLANG)
    :return: The chaincode pkg path or None
    """
    _logger.debug('Packaging chaincode path={}, chaincode type={}'.format(
        cc_path, cc_type))

    if not cc_path:
        raise ValueError("Missing chaincode path parameter "
                         "in install proposal request")

    if cc_type == CC_TYPE_GOLANG:
        go_path = os.environ['GOPATH']

        if not go_path:
            raise ValueError("No GOPATH env variable is found")

        proj_path = go_path + '/src/' + cc_path
        _logger.debug('Project path={}'.format(proj_path))

        code_content = _tar_path(proj_path, go_path)
        if code_content:
            return code_content
        else:
            raise ValueError('No chaincode found')

    elif cc_type == CC_TYPE_NODE:

        proj_path = cc_path
        _logger.debug('Project path={}'.format(proj_path))

        code_content = _tar_path(proj_path)
        if code_content:
            return code_content
        else:
            raise ValueError('No chaincode found')

    else:
        raise ValueError(f'Currently only support install {CC_TYPE_GOLANG}, {CC_TYPE_NODE} chaincodes')


def _get_tar_info(file_name, file_bytes):
    code_info = tarfile.TarInfo(file_name)
    code_info.size = len(file_bytes)
    return code_info


def lifecycle_package(code_archive, metadata):
    tar_stream = io.BytesIO()
    with tarfile.open(fileobj=tar_stream, mode='w|gz', format=tarfile.GNU_FORMAT) as dist:
        dist.addfile(_get_tar_info("code.tar.gz", code_archive), io.BytesIO(code_archive))

        metadata_bytes = json.dumps(metadata).encode()
        dist.addfile(_get_tar_info("metadata.json", metadata_bytes), io.BytesIO(metadata_bytes))
    tar_stream.seek(0)
    return tar_stream.read()
