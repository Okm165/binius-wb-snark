import init, { run as biniusProveAndVerifyKeccakTrace } from "binius-keccak";

export interface WorkerMessage {
    values: string[];
}

export interface WorkerResponse {
    values?: string[];
    error?: string;
}

self.onmessage = async (event: MessageEvent<WorkerMessage>) => {
    const { values } = event.data;

    try {
        await init();
        let hash = await biniusProveAndVerifyKeccakTrace(values);

        // Send results back to the main thread
        const response: WorkerResponse = { values: hash };
        self.postMessage(response);
    } catch (error) {
        // Send error back to the main thread
        const response: WorkerResponse = { error: (error as Error).message };
        self.postMessage(response);
    }
};