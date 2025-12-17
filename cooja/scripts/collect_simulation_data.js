/*
 * Cooja Script for Automated Data Collection
 * Runs simulation and exports flow data to CSV
 */

// Configuration
var SIMULATION_TIME = 600000; // 600 seconds (10 minutes)
var OUTPUT_FILE = "testbed_data.csv";

// Open output file
var outputFile = new java.io.FileWriter(OUTPUT_FILE);
var writer = new java.io.BufferedWriter(outputFile);

// Write CSV header
writer.write("flow_duration,fwd_pkts,bwd_pkts,fwd_bytes,bwd_bytes,");
writer.write("fwd_pkt_len_mean,bwd_pkt_len_mean,flow_bytes_s,flow_pkts_s,");
writer.write("fwd_iat_mean,fwd_iat_min,fwd_iat_max,");
writer.write("pkt_len_min,pkt_len_max,pkt_len_mean,");
writer.write("syn,fin,rst,psh,ack,");
writer.write("down_up_ratio,pkt_count,byte_count,high_rate_flag,label\n");

var flowCount = 0;
var normalCount = 0;
var attackCount = 0;

// Timeout function
TIMEOUT(SIMULATION_TIME, function() {
    log.log("Simulation complete!\n");
    log.log("Total flows collected: " + flowCount + "\n");
    log.log("Normal: " + normalCount + ", Attack: " + attackCount + "\n");
    
    writer.close();
    log.testOK();
});

// Main loop - process messages
while(true) {
    YIELD();
    
    // Check for FLOW_DATA messages
    var msg = msg.toString();
    
    if(msg.indexOf("FLOW_DATA,") >= 0) {
        // Extract flow data
        var dataStart = msg.indexOf("FLOW_DATA,") + 10;
        var flowData = msg.substring(dataStart).trim();
        
        // Write to file
        writer.write(flowData + "\n");
        writer.flush();
        
        flowCount++;
        
        // Count by label (last value)
        var parts = flowData.split(",");
        if(parts.length >= 25) {
            var label = parseInt(parts[24]);
            if(label == 0) {
                normalCount++;
            } else {
                attackCount++;
            }
        }
        
        // Progress report every 100 flows
        if(flowCount % 100 == 0) {
            log.log("Collected " + flowCount + " flows (Normal: " + 
                    normalCount + ", Attack: " + attackCount + ")\n");
        }
    }
}
