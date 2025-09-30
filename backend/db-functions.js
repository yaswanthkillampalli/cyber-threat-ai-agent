/**
 * db-functions.js
 * (Complete Version of saveAnalysisResults with final schema fix)
 */

// --- FLOW FEATURE MAPPING ---
// Map keys from the incoming JS object (long form) to the SQL column name (short form).
// This mapping resolves the 'ack_flag_cnt' error and similar conflicts for ALL 70+ features.
const COLUMN_DB_MAP = {
    // Note: The key is the JavaScript property name (what's in your CSV/JSON flow object).
    // The value is the PostgreSQL column name (what's in your DDL).
    
    // Core Traffic Totals (Likely cause of the error)
    'total_fwd_packets': 'tot_fwd_pkts',
    'total_backward_packets': 'tot_bwd_pkts',
    'total_length_of_fwd_packets': 'totlen_fwd_pkts',
    'total_length_of_bwd_packets': 'totlen_bwd_pkts',

    // Packet Length Stats
    'fwd_packet_length_max': 'fwd_pkt_len_max',
    'fwd_packet_length_min': 'fwd_pkt_len_min',
    'fwd_packet_length_mean': 'fwd_pkt_len_mean',
    'fwd_packet_length_std': 'fwd_pkt_len_std',
    'bwd_packet_length_max': 'bwd_pkt_len_max',
    'bwd_packet_length_min': 'bwd_pkt_len_min',
    'bwd_packet_length_mean': 'bwd_pkt_len_mean',
    'bwd_packet_length_std': 'bwd_pkt_len_std',

    // Flow Rates (Must use quotes in SQL but mapped here without quotes)
    'flow_bytes_s': 'flow_byts_s',
    'flow_pkts_s': 'flow_pkts_s',
    'fwd_pkts_s': 'fwd_pkts_s',
    'bwd_pkts_s': 'bwd_pkts_s',

    // IAT Totals
    'fwd_iat_total': 'fwd_iat_tot',
    'bwd_iat_total': 'bwd_iat_tot',

    // Header Lengths
    'fwd_header_length': 'fwd_header_len',
    'bwd_header_length': 'bwd_header_len',
    
    // Flags (The key source of conflict)
    'fin_flag_count': 'fin_flag_cnt',
    'syn_flag_count': 'syn_flag_cnt',
    'rst_flag_count': 'rst_flag_cnt',
    'psh_flag_count': 'psh_flag_cnt',
    'ack_flag_count': 'ack_flag_cnt', // 🛑 FIX: This maps the long JS name to the short SQL name
    'urg_flag_count': 'urg_flag_cnt',

    // Packet Length/Size
    'min_packet_length': 'pkt_len_min',
    'max_packet_length': 'pkt_len_max',
    'packet_length_mean': 'pkt_len_mean',
    'packet_length_std': 'pkt_len_std',
    'packet_length_variance': 'pkt_len_var',
    'average_packet_size': 'pkt_size_avg',

    // Bulk/Segment
    'fwd_seg_size_avg': 'fwd_seg_size_avg',
    'bwd_seg_size_avg': 'bwd_seg_size_avg',
    'fwd_avg_bytes_bulk': 'fwd_byts_b_avg',
    'fwd_avg_packets_bulk': 'fwd_pkts_b_avg',
    'fwd_avg_bulk_rate': 'fwd_blk_rate_avg',
    'bwd_avg_bytes_bulk': 'bwd_byts_b_avg',
    'bwd_avg_packets_bulk': 'bwd_pkts_b_avg',
    'bwd_avg_bulk_rate': 'bwd_blk_rate_avg',
    'subflow_fwd_pkts': 'subflow_fwd_pkts',
    'subflow_fwd_byts': 'subflow_fwd_byts',
    'subflow_bwd_pkts': 'subflow_bwd_pkts',
    'subflow_bwd_byts': 'subflow_bwd_byts',
    'init_fwd_win_byts': 'init_fwd_win_byts',
    'init_bwd_win_byts': 'init_bwd_win_byts',
    'fwd_act_data_pkts': 'fwd_act_data_pkts',
    'fwd_seg_size_min': 'fwd_seg_size_min',
    
    // CWE is already fully spelled out in SQL but often comes in as 'cwe_flag_count'
    'cwe_flag_count': 'cwe_flag_count', 
    // ECE flag is already short
    'ece_flag_cnt': 'ece_flag_cnt',

    // Down/Up Ratio - common conflict
    'down_up_ratio': 'down_up_ratio',

    // Active/Idle (Assuming names match schema)
    // 'active_mean': 'active_mean' (no change)
};


/**
 * Inserts an array of predicted network flow data rows into the analysis_results table.
 */
async function saveAnalysisResults(supabase, analysisId, predictedRows) {
    if (!predictedRows || predictedRows.length === 0) {
        console.warn(`No rows to save for analysis ID: ${analysisId}`);
        return false;
    }

    const rowsToInsert = predictedRows.map(row => {
        const mappedRow = {};

        // Loop through all keys in the incoming row
        for (const key in row) {
            if (row.hasOwnProperty(key)) {
                // Determine the correct DB column name
                const dbColumnName = COLUMN_DB_MAP[key] || key;
                
                // Assign the value using the database column name
                mappedRow[dbColumnName] = row[key];
            }
        }
        
        return mappedRow;
    });

    console.log(`Attempting to save ${rowsToInsert.length} results for Analysis ID ${analysisId}...`);

    // Perform the bulk insert operation
    const { error } = await supabase
        .from('analysis_results')
        .insert(rowsToInsert);

    if (error) {
        console.error("Supabase Error: Failed to save analysis results (Schema Mismatch):", error.message);
        if (error.details) {
            console.error("Supabase Error Details:", error.details);
        }
        return false;
    } else {
        console.log(`Successfully saved ${rowsToInsert.length} analysis results to Supabase.`);
        return true;
    }
}


/**
 * Checks the defense_rules table to see if the given IP address is currently blocked.
 * @param {object} supabase - The initialized Supabase client object.
 * @param {string} ipAddress - The IP address to check.
 * @returns {Promise<boolean>} - True if the IP is actively blocked, false otherwise.
 */
async function checkDefenseRule(supabase, ipAddress) {
    if (!ipAddress || ipAddress === 'UNKNOWN') {
        return false; // Cannot block an unknown or missing IP
    }

    // 1. Query the 'defense_rules' table
    const { data, error } = await supabase
        .from('defense_rules')
        .select('ip_address') // Select only the column needed (for speed)
        .eq('ip_address', ipAddress) // Match the IP
        .eq('is_active', true) // Rule must be active
        .gt('expires_at', new Date().toISOString()) // Expiration must be in the future
        .limit(1); // Stop after finding the first match

    if (error) {
        console.error("Supabase Error: Failed to check defense rule:", error.message);
        return false; 
    }

    // If data array has at least one result, the IP is blocked.
    return data.length > 0; 
}


/**
 * Retrieves all rows from the analysis_results table for a specific job ID.
 * @param {object} supabase - The initialized Supabase client object.
 * @param {string} analysisId - The analysis job ID (UUID).
 * @returns {Promise<Array<object>|null>} - The list of rows, ordered by insertion time, or null on error.
 */
async function getAnalysisResultsByJobId(supabase, analysisId) {
    const { data, error } = await supabase
        .from('analysis_results')
        .select('*')
        .eq('analysis_id', analysisId)
        .order('created_at', { ascending: true }); // Ascending order as requested

    if (error) {
        console.error(`Supabase Error: Failed to fetch results for ID ${analysisId}:`, error.message);
        return null;
    }
    
    // The data structure contains all the columns, including prediction and all flow features.
    return data;
}

module.exports = {
    saveAnalysisResults,
    checkDefenseRule,
    getAnalysisResultsByJobId
};