import init, { run_sha3 } from "binius-web-snark";

export interface WorkerMessage {
    value: string;
}

interface Output {
    hash: string,
    transcript: string,
    advice: string,
}

export interface WorkerResponse {
    value?: Output;
    error?: string;
}

self.onmessage = async (event: MessageEvent<WorkerMessage>) => {
    const { value } = event.data;

    try {
        await init();
        const hash = await run_sha3(value);

        // Send results back to the main thread
        const response: WorkerResponse = { value: hash };
        self.postMessage(response);
    } catch (error) {
        // Send error back to the main thread
        const response: WorkerResponse = { error: (error as Error).message };
        self.postMessage(response);
    }
};