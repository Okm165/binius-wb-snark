"use client";

import { useRef, useState } from "react";
import { WorkerMessage, WorkerResponse } from "@/worker_sha3";
import { Box, Button, Typography } from "@mui/material";
import CircularProgress from "@mui/material/CircularProgress";

export default function Home() {
  const workerRef = useRef<Worker>(null);
  const [timeSHA2, setTimeSHA2] = useState<number | null>(null);
  const [timeSHA3, setTimeSHA3] = useState<number | null>(null);
  const [isLoadingSHA2, setIsLoadingSHA2] = useState<boolean>(false);
  const [isLoadingSHA3, setIsLoadingSHA3] = useState<boolean>(false);
  const [input, setInput] = useState<string>("");
  const [hash, setHash] = useState<string>("");

  const randomInput = () => {
    // Generate 32 random bytes
    const randomBytes = new Uint8Array(64);
    crypto.getRandomValues(randomBytes);

    // Convert to a hexadecimal string
    const randomHex = Array.from(randomBytes)
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");

    setInput(randomHex);
  }

  const biniusProveAndVerifySHA3 = async () => {
    setIsLoadingSHA3(true);

    workerRef.current = new Worker(new URL("../worker_sha3.ts", import.meta.url), {
      type: "module",
    });

    const startTime = Date.now();

    workerRef.current.onmessage = (event: MessageEvent<WorkerResponse>) => {
      const { value, error } = event.data;

      if (error) {
        console.error(error);
      } else if (value) {
        setHash(value);
      }

      const endTime = Date.now();
      const elapsedTime = endTime - startTime;
      setTimeSHA3(elapsedTime);

      workerRef.current?.terminate();

      setIsLoadingSHA3(false);
    };

    const message: WorkerMessage = {
      value: input,
    };

    workerRef.current.postMessage(message);
  };

  const biniusProveAndVerifySHA2 = async () => {
    setIsLoadingSHA2(true);

    workerRef.current = new Worker(new URL("../worker_sha2.ts", import.meta.url), {
      type: "module",
    });

    const startTime = Date.now();

    workerRef.current.onmessage = (event: MessageEvent<WorkerResponse>) => {
      const { value, error } = event.data;

      if (error) {
        console.error(error);
      } else if (value) {
        setHash(value);
      }

      const endTime = Date.now();
      const elapsedTime = endTime - startTime;
      setTimeSHA2(elapsedTime);

      workerRef.current?.terminate();

      setIsLoadingSHA2(false);
    };

    const message: WorkerMessage = {
      value: input,
    };

    workerRef.current.postMessage(message);
  };

  return (
    <div className="grid gap-6 p-4 max-w-[800px] m-auto">
      <h1 className="text-2xl font-bold text-center text-gray-300">
        Binius Keccak256 - Prove and Verify - SNARK demo
      </h1>
      <textarea
        onChange={(e) => {
          setInput(e.target.value);
        }}
        value={input}
        className="p-0 bg-gray-900 text-sm resize-both h-32"
      />
      <div className="grid grid-flow-row justify-center gap-4">
        <div className="grid grid-flow-row justify-center gap-4">
          <Button
            size="small"
            disabled={isLoadingSHA3 || isLoadingSHA2}
            onClick={async () => {
              randomInput();
            }}
          >
            <Box display="flex" flexDirection="column" alignItems="center">
              <Typography variant="body2">generate random input</Typography>
            </Box>
          </Button>
        </div>
        <div className="grid grid-flow-row justify-center gap-4">
          <Button
            sx={{
              color: "#F2A900",
              borderColor: "#473200",
              height: 50,
              "&:hover": {
                borderColor: "#634500",
              },
            }}
            variant="outlined"
            size="small"
            disabled={isLoadingSHA3 || isLoadingSHA2}
            onClick={async () => {
              biniusProveAndVerifySHA2();
            }}
          >
            {isLoadingSHA2 ? (
              <CircularProgress
                size={24}
                sx={{ color: "#F2A900", animationDuration: "700ms" }}
              />
            ) : (
              <Box display="flex" flexDirection="column" alignItems="center">
                <Typography variant="body2">sha256 prove verify</Typography>
              </Box>
            )}
          </Button>
          <div className="grid justify-center gap-1 text-xs">
            {timeSHA2 !== null ? `Time: ${timeSHA2 / 1000} seconds` : null}
          </div>
        </div>
        <div className="grid grid-flow-row justify-center gap-4">
          <Button
            sx={{
              color: "#F2A900",
              borderColor: "#473200",
              height: 50,
              "&:hover": {
                borderColor: "#634500",
              },
            }}
            variant="outlined"
            size="small"
            disabled={isLoadingSHA3 || isLoadingSHA2}
            onClick={async () => {
              biniusProveAndVerifySHA3();
            }}
          >
            {isLoadingSHA3 ? (
              <CircularProgress
                size={24}
                sx={{ color: "#F2A900", animationDuration: "700ms" }}
              />
            ) : (
              <Box display="flex" flexDirection="column" alignItems="center">
                <Typography variant="body2">keccak prove verify</Typography>
              </Box>
            )}
          </Button>
          <div className="grid justify-center gap-1 text-xs">
            {timeSHA3 !== null ? `Time: ${timeSHA3 / 1000} seconds` : null}
          </div>
        </div>

      </div>

      <textarea
        className="p-0 bg-gray-900 text-sm resize-both h-32"
        value={hash}
        readOnly
      />
    </div>
  );
}
