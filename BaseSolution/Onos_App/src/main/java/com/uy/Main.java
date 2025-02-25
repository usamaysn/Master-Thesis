package com.uy;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

public class Main {
    private static final String ONOS_URL = "http://172.17.0.2:8181/onos/v1/";
    private static final String USERNAME = "onos";
    private static final String PASSWORD = "rocks";
    private static final String PYTHON_INTERPRETER = "/usr/bin/python3"; // Update this path to your Python interpreter
    private static final String DDOS_DETECT_SCRIPT = "/home/sdn/ddos_detect.py"; // Update this path to your ddos_detect.py script
    private static final int SCRIPT_TIMEOUT = 600; // Timeout for the script in seconds (10 minutes)
    private static final String BLOCKLIST_CSV = "/home/sdn/ddos_blocklist.csv"; // Path to the blocklist CSV file

    public static void main(String[] args) {
        try {
            System.out.println("Running Python script for DDoS detection...");

            // Run the Python script to analyze the captured data
            String command = PYTHON_INTERPRETER + " " + DDOS_DETECT_SCRIPT;
            String result = runPythonScript(command, SCRIPT_TIMEOUT);
            System.out.println("Python script output:\n" + result);

            // Create the blocklist CSV file
            createBlocklistCSV(result, BLOCKLIST_CSV);
            System.out.println("Blocklist CSV created at " + BLOCKLIST_CSV);



            // Read blocklist and apply rules to ONOS
            applyBlocklist(BLOCKLIST_CSV);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String runPythonScript(String command, int timeoutSeconds) throws Exception {
        System.out.println("Running command: " + command);
        Process process = Runtime.getRuntime().exec(command);
        BufferedReader stdInput = new BufferedReader(new InputStreamReader(process.getInputStream()));
        BufferedReader stdError = new BufferedReader(new InputStreamReader(process.getErrorStream()));

        // Wait for the process to complete with a timeout
        if (!process.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
            // Process timed out, destroy it
            process.destroy();
            throw new RuntimeException("Python script execution timed out.");
        }

        String s;
        StringBuilder output = new StringBuilder();
        while ((s = stdInput.readLine()) != null) {
            output.append(s).append("\n");
        }
        while ((s = stdError.readLine()) != null) {
            System.err.println(s);
        }

        int exitCode = process.waitFor();
        if (exitCode != 0) {
            throw new RuntimeException("Python script execution failed. Exit code: " + exitCode);
        }

        return output.toString();
    }

    private static void createBlocklistCSV(String scriptOutput, String csvFilePath) throws IOException {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(csvFilePath))) {
            // Write header for the CSV file
            writer.write("Source IP,Count\n");

            // Process the Python script output
            String[] lines = scriptOutput.split("\n");
            boolean startCapturing = false;

            for (String line : lines) {
                // Look for the start of the relevant section in the script output
                if (line.contains("Source IPs and their counts for DDoS traffic:")) {
                    startCapturing = true;
                    continue;
                }

                // Skip unnecessary lines until we reach the relevant section
                if (!startCapturing || line.trim().isEmpty() || line.startsWith("Source IP")) {
                    continue;
                }

                // Stop capturing when reaching the end of the relevant section
                if (line.startsWith("Name:")) {
                    break;
                }

                // Write source IP and count to the CSV file
                String[] parts = line.trim().split("\\s+");
                if (parts.length == 2) {
                    writer.write(parts[0] + "," + parts[1] + "\n");
                }
            }
        }
    }

    private static void applyBlocklist(String csvFilePath) {
        String ipToBlock = null;
        int maxCount = 0;

        try (BufferedReader br = new BufferedReader(new FileReader(csvFilePath))) {
            String line;
            // Skip the header
            br.readLine();
            while ((line = br.readLine()) != null) {
                String[] parts = line.split(",");
                if (parts.length == 2) {
                    String srcIp = parts[0].trim();
                    int count = Integer.parseInt(parts[1].trim());

                    // Check if this IP has the highest count
                    if (count > maxCount) {
                        maxCount = count;
                        ipToBlock = srcIp;
                    }
                }
            }
            if (ipToBlock != null) {
                // Block the IP with the highest count
                addBlockRuleToOnos(ipToBlock);
                System.out.println("Blocked IP with highest count: " + ipToBlock);
            } else {
                System.out.println("No IPs to block.");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void addBlockRuleToOnos(String srcIp) {
        try {
            String endpoint = "flows";
            URL url = new URL(ONOS_URL + endpoint);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setDoOutput(true);
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Authorization", "Basic " + encodeCredentials(USERNAME, PASSWORD));

            String jsonPayload = buildJsonPayload(srcIp);
            // Print the JSON payload for debugging
            System.out.println("JSON Payload: " + jsonPayload);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(jsonPayload.getBytes());
                os.flush();
            }
            int responseCode = conn.getResponseCode();
            if (responseCode != HttpURLConnection.HTTP_OK) {
                // Print error details
                BufferedReader br = new BufferedReader(new InputStreamReader(conn.getErrorStream()));
                String line;
                StringBuilder errorResponse = new StringBuilder();
                while ((line = br.readLine()) != null) {
                    errorResponse.append(line).append("\n");
                }
                System.out.println("Error response from ONOS: " + errorResponse.toString());

                throw new RuntimeException("Failed to add flow rule. HTTP error code : " + responseCode);
            }

            conn.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    private static String buildJsonPayload(String srcIp) {
        return "{\n" +
                "  \"flows\": [\n" +
                "    {\n" +
                "      \"priority\": 40000,\n" +
                "      \"timeout\": 0,\n" +
                "      \"isPermanent\": true,\n" +
                "      \"deviceId\": \"of:0000000000000001\",\n" +
                "      \"treatment\": {\n" +
                "        \"instructions\": []\n" +  // Empty array implies drop by default
                "      },\n" +
                "      \"selector\": {\n" +
                "        \"criteria\": [\n" +
                "          {\n" +
                "            \"type\": \"IPV4_SRC\",\n" +
                "            \"ip\": \"" + srcIp + "/32\"\n" +
                "          }\n" +
                "        ]\n" +
                "      }\n" +
                "    }\n" +
                "  ]\n" +
                "}";
    }


    private static String fetchFromOnos(String endpoint) throws Exception {
        URL url = new URL(ONOS_URL + endpoint);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Accept", "application/json");
        conn.setRequestProperty("Authorization", "Basic " + encodeCredentials(USERNAME, PASSWORD));

        if (conn.getResponseCode() != 200) {
            throw new RuntimeException("Failed : HTTP error code : " + conn.getResponseCode());
        }

        BufferedReader br = new BufferedReader(new InputStreamReader((conn.getInputStream())));
        StringBuilder sb = new StringBuilder();
        String output;
        while ((output = br.readLine()) != null) {
            sb.append(output).append("\n");
        }

        conn.disconnect();
        return sb.toString();
    }




    private static String encodeCredentials(String username, String password) {
        return Base64.getEncoder().encodeToString((username + ":" + password).getBytes());
    }
}
