FROM python:2.7

COPY contrib /tmp/contrib
COPY setup.py /tmp/
COPY cacus /tmp/cacus

# This is because of some cock sucking contest between azure libs developers, setuptools,
# python image maintainers that using jessie etc
RUN pip install chardet azure-common azure-storage
RUN cd /tmp && python setup.py install

EXPOSE 1488

ENTRYPOINT ["cacus", "-c", "/cacus/config.yml"]
