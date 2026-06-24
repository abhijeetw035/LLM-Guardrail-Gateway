# LLM Guardrail Gateway - Resume Points

You can include the following bullet points in your resume to highlight the architectural, performance, and engineering skills demonstrated in this project:

## **Backend / Systems Engineer (Go, High-Performance Systems)**

*   **Designed and developed a high-performance LLM Guardrail Gateway** in Go, serving as an intermediate reverse-proxy for streaming LLM responses (e.g., OpenAI, Anthropic) with real-time payload inspection.
*   **Engineered a custom Policy Domain-Specific Language (DSL)** from scratch using a hand-written Lexer, Parser, and AST evaluator, enabling dynamic rule enforcement (regex, token counts, JSON validation) without proxy restarts.
*   **Implemented a concurrent Sliding Window algorithm** to scan chunked Server-Sent Events (SSE) streams in real-time, detecting multi-token malicious patterns (e.g., prompt injections) with less than 2ms overhead.
*   **Built a distributed Rate Limiting and Quota Management system** using Redis and the Token Bucket algorithm, supporting multitenant usage with high scalability and low latency.
*   **Achieved robust performance and reliability** verified through comprehensive fuzz testing (Go Fuzzing) and high-concurrency Vegeta load tests, managing 500+ concurrent streaming connections effortlessly.
*   **Integrated comprehensive observability** using Prometheus and Grafana, providing real-time metrics on token latency, request throughput, rule violation rates, and sliding window delays.
*   **Containerized the entire stack** using Docker and Docker Compose, streamlining deployments and facilitating isolated integration testing environments.

## **Key Skills to Highlight**
*   **Languages:** Go (Golang)
*   **Systems Architecture:** Reverse Proxies, Stream Processing (SSE), Sliding Window Algorithms, Custom DSLs, AST Evaluation
*   **Databases / Caching:** Redis (Rate Limiting, Quotas)
*   **Testing:** Go Benchmarks, Fuzz Testing, Vegeta (Load Testing)
*   **Observability:** Prometheus, Grafana
*   **DevOps:** Docker, Docker Compose

## **Tips for Interviews**
*   **Be ready to explain the Sliding Window:** Interviewers love algorithmic challenges. Explain how you handled chunks breaking tokens in half (e.g., detecting "ignore previous instructions" when "ignore pre" and "vious instructions" arrive in separate SSE frames).
*   **Discuss the DSL:** Building a lexer and parser from scratch shows deep computer science fundamentals. Mention why you chose a custom DSL over just JSON configs (e.g., expressiveness, strong typing for conditions).
*   **Highlight the performance impact:** Use the actual latency numbers from the `make bench` and `make load` reports. Saying "Added only ~X ms of overhead at P99 while processing streaming chunks" is very impressive.
