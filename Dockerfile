FROM python:2.7

COPY cacus /tmp/cacus
COPY contrib /tmp/contrib
COPY setup.py /tmp/

# This is because of some cock sucking contest between azure libs developers, setuptools,
# python image maintainers that using jessie etc
RUN pip install chardet azure-common azure-storage
RUN cd /tmp && python setup.py install

EXPOSE 1488

CMD cacus -c /cacus/config.yml --repo-daemon
ENTRYPOINT ["cacus" "-c" "/cacus/config.yml"]
