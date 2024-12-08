"use client"

import { useRef, useState } from "react";
import { WorkerMessage, WorkerResponse } from "@/worker";
import { Box, Button, Typography } from "@mui/material";
import CircularProgress from "@mui/material/CircularProgress";

export default function Home() {
  const workerRef = useRef<Worker>(null);
  const [time, setTime] = useState<number | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [inputs, setInputs] = useState<string[]>(Array(25).fill(""));
  const [hashes, setHashes] = useState<string[]>(Array(25).fill(""));

  const generateRandomInputs = () => {
    const randomIntegers = Array.from({ length: 25 }, () =>
      Math.floor(Math.random() * 1000000000).toString()
    );
    setTime(null);
    setInputs(randomIntegers);
    setHashes(Array(25).fill(""));
  };

  const biniusProveAndVerifyKeccakTrace = async () => {
    setIsLoading(true);

    workerRef.current = new Worker(new URL("../worker.ts", import.meta.url), {
      type: "module",
    });

    const startTime = Date.now();

    workerRef.current.onmessage = (event: MessageEvent<WorkerResponse>) => {
      const { values, error } = event.data;

      if (error) {
        console.error(error);
      } else if (values) {
        setHashes(values);
      }

      const endTime = Date.now();
      const elapsedTime = endTime - startTime;
      setTime(elapsedTime);

      workerRef.current?.terminate();

      setIsLoading(false)
    };

    const message: WorkerMessage = {
      values: inputs,
    };

    workerRef.current.postMessage(message);
  };

  return (
    <div className="grid gap-6 p-4">
      <h1 className="text-2xl font-bold text-center text-gray-300">
        Binius Keccak256 - Prove and Verify - SNARK demo
      </h1>
      <div className="grid grid-cols-[repeat(auto-fill,minmax(150px,1fr))] gap-1 text-xs">
        {inputs.map((value, index) => (
          <input
            key={index}
            type="text"
            value={value}
            onChange={(e) => {
              const newInputs = [...inputs];
              newInputs[index] = e.target.value;
              setInputs(newInputs);
            }}
            className="p-0 bg-gray-900 text-xs"
          />
        ))}
      </div>
      <div className="grid grid-flow-row justify-center gap-4">
        <Button
          sx={{
            height: 50,
          }}
          variant="outlined"
          size="small"
          onClick={async () => {
            generateRandomInputs();
          }}
        >
          <Box display="flex" flexDirection="column" alignItems="center">
            <Typography variant="body2">generate random inputs</Typography>
          </Box>
        </Button>
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
          disabled={isLoading}
          onClick={async () => {
            biniusProveAndVerifyKeccakTrace();
          }}
        >
          {isLoading ? (
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
      </div>
      <div className="grid justify-center gap-1 text-xs">
        {time !== null ? `Time: ${time/1000} seconds` : null}
      </div>
      <div className="grid grid-cols-[repeat(auto-fill,minmax(150px,1fr))] gap-1 text-xs">
        {hashes.map((hash, index) => (
          <div
            key={index}
            className="p-0 bg-gray-900 text-xs"
          >
            {hash}
          </div>
        ))}
      </div>
    </div>
  );
}
