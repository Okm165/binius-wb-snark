import init, { run_sha2 } from "binius-keccak";

export interface WorkerMessage {
    value: string;
}

export interface WorkerResponse {
    value?: string;
    error?: string;
}

self.onmessage = async (event: MessageEvent<WorkerMessage>) => {
    const { value } = event.data;

    try {
        await init();
        const hash = await run_sha2(value);

        // Send results back to the main thread
        const response: WorkerResponse = { value: hash };
        self.postMessage(response);
    } catch (error) {
        // Send error back to the main thread
        const response: WorkerResponse = { error: (error as Error).message };
        self.postMessage(response);
    }
};