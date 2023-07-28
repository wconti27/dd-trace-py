from ddtrace.internal import core

core.on("kafka.produce.start", kafka_message_producer_span_info)
core.on("kafka.produce.start.span", kafka_producer_start)
core.on("kafka.produce.finish", kafka_message_producer_span_info)
core.on("kafka.produce.finish.span", kafka_producer_finish)
