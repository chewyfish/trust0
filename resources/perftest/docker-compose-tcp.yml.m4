version: '3.8'

services:

  t0perf-t0gateway1:
    image: trust0-gateway:latest
    command: --config-file /app/config/t0perf-t0gateway1.rc full-gateway
    user: xUID:xGID
    volumes:
      - xPERFTEST_BUILD_DIR:/app/config
    networks:
      - t0net-xRUNKEY

  t0perf-t0client1:
    image: trust0-client:latest
    command: --config-file /app/config/t0perf-t0client1.rc --script-file /app/config/t0perf-t0client-commands.txt
    depends_on:
      t0perf-t0gateway1:
        condition: service_started
    restart: on-failure:5
    user: xUID:xGID
    volumes:
      - xPERFTEST_BUILD_DIR:/app/config
    networks:
      - t0net-xRUNKEY
    stdin_open: true
    tty: true

  t0perf-service1:
    image: fortio/fortio
    command: server
    networks:
      - t0net-xRUNKEY

  t0perf-tcp-client1:
    image: fortio/fortio
    command: load -qps xQPS_PER_TRANSPORT -c xCONNECTIONS_PER_TRANSPORT -t xMAX_EXECUTION_TIME_MIN tcp://t0perf-t0client1:8501
    depends_on:
      t0perf-t0client1:
        condition: service_started
      t0perf-service1:
        condition: service_started
    restart: on-failure:5
    networks:
      - t0net-xRUNKEY

networks:
  t0net-xRUNKEY:
