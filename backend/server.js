// server.js (Final Comprehensive Version)

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const Papa = require('papaparse');
const axios = require('axios');
const { v4: uuidv4 } = require('uuid');
const saveAnalysisResults = require('./db-functions').saveAnalysisResults;
const createDefenseRule = require('./db-functions').createDefenseRule;
const { getAnalysisResultsByJobId } = require('./db-functions');
const { createClient } = require('@supabase/supabase-js');
const { transformPredictionData, transformBlockedData } = require('./analysis-transformer.js');

// --- CONFIGURATION ---
const PORT = process.env.PORT || 8000;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_ANON_KEY;
const MODEL_API_URL_SINGLE = process.env.MODEL_API_URL_SINGLE;
const MODEL_API_URL_BATCH = process.env.MODEL_API_URL_BATCH;

// --- INITIALIZATION ---
const app = express();
app.use(cors());
app.use(express.json()); // Middleware to parse JSON bodies
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// --- NEW: THREAT AGGREGATION CONFIGURATION ---
const THRESHOLD_COUNT = 50;       // N: Detections required to create a rule
const THRESHOLD_WINDOW_MS = 10000; // T: Time window (10 seconds) in milliseconds
const RULE_EXPIRATION_MINUTES = 60; // Rule blocks for 1 hour
const DIAGNOSTIC_FORCE_ATTACK = false; // Set to true for debugging prediction/model issues

// In-memory store for tracking recent attack detections by IP
const RECENT_ATTACK_TRACKER = {}; 

// Setup periodic cleanup for the tracker (runs every 5 minutes)
// This is essential for preventing memory leaks in a real application.
setInterval(() => {
    const currentTime = Date.now();
    for (const ip in RECENT_ATTACK_TRACKER) {
        RECENT_ATTACK_TRACKER[ip] = RECENT_ATTACK_TRACKER[ip].filter(
            timestamp => (currentTime - timestamp) <= THRESHOLD_WINDOW_MS
        );
        if (RECENT_ATTACK_TRACKER[ip].length === 0) {
            delete RECENT_ATTACK_TRACKER[ip];
        }
    }
}, 5 * 60 * 1000); 


// --- NEW CRITICAL FUNCTION: Rule Management ---
async function manageDefenseRules(supabase, row, prediction, jobId) {
    const ipAddress = row.src_ip || row.dst_ip;
    const currentTime = Date.now();
    const flowId = row.flow_id || 'N/A'; 

    // 1. ROBUST TIME EXTRACTION
    const timeFields = [row.timestamp, row.created_at, row.Timestamp, row.createdAt];
    let flowTime = NaN;
    for (const timeStr of timeFields) {
        if (timeStr) {
            const parsedTime = new Date(timeStr).getTime();
            if (!isNaN(parsedTime)) {
                flowTime = parsedTime;
                break;
            }
        }
    }
    if (!ipAddress || ipAddress === 'UNKNOWN' || isNaN(flowTime)) {
        // Log the exact error if the time parsing fails (as it did before)
        console.error(`ERROR: Skipping rule check for flow ${flowId}. Could not parse valid time from:`, timeFields);
        return false; 
    }
    
    // 2. AGGREGATION LOGIC
    if (!RECENT_ATTACK_TRACKER[ipAddress]) {
        RECENT_ATTACK_TRACKER[ipAddress] = [];
    }
    
    const recentDetections = RECENT_ATTACK_TRACKER[ipAddress].filter(
        timestamp => (flowTime - timestamp) <= THRESHOLD_WINDOW_MS && (flowTime - timestamp) >= 0 
    );
    recentDetections.push(flowTime);
    RECENT_ATTACK_TRACKER[ipAddress] = recentDetections;

    // 3. CHECK THRESHOLD (5 hits in 10 seconds)
    if (recentDetections.length >= THRESHOLD_COUNT) {
        
        console.log(`AGGREGATION MET: IP ${ipAddress} hit ${recentDetections.length} times. Checking DB.`);

        let existingRules = null;
        let rulesError = null;

        // 4. CHECK FOR EXISTING RULE (Simple check to prevent duplicates)
        try {
            const result = await supabase
                .from('defense_rules')
                .select('ip_address')
                .eq('ip_address', ipAddress)
                .limit(1); 
            
            existingRules = result.data;
            rulesError = result.error;
        } catch (e) {
            console.error(`🚨 FATAL DB CHECK EXCEPTION for ${ipAddress} (Query):`, e.message);
            return false;
        }

        if (rulesError) {
            console.error(`🚨 SUPABASE QUERY ERROR during rule check for ${ipAddress}:`, rulesError.message);
            return false;
        }
        
        // 5. ATTEMPT RULE CREATION
        if (!existingRules || existingRules.length === 0) {
            
            const expiresAt = new Date(currentTime + RULE_EXPIRATION_MINUTES * 60 * 1000).toISOString();

            const ruleToInsert = {
                ip_address: ipAddress,
                threat_type: prediction,
                expires_at: expiresAt,
                is_active: true,
                analysis_id: jobId, // This is the UUID from the analysis_jobs table
                raw_flow_data: { trigger_flow_id: flowId, threat_count: recentDetections.length }, 
            };
            
            const { error: insertError } = await supabase
                .from('defense_rules')
                .insert([ruleToInsert]); 
            
            if (!insertError) {
                console.log(`✅🛡️ RULE CREATED SUCCESSFULLY for ${ipAddress}. Threat: ${prediction}.`); 
                delete RECENT_ATTACK_TRACKER[ipAddress];
                return true;
            } else {
                console.error(`🚨 FATAL DB INSERTION ERROR for ${ipAddress}:`, insertError.message);
                if (insertError.details) {
                    console.error('DB Insert Details:', insertError.details);
                }
                return false;
            }
        } else {
            console.log(`⏭️ RULE SKIP: Rule already exists for IP ${ipAddress}. Not creating new rule.`);
        }
    }
    return false;
}

setInterval(() => {
    const currentTime = Date.now();
    for (const ip in RECENT_ATTACK_TRACKER) {
        RECENT_ATTACK_TRACKER[ip] = RECENT_ATTACK_TRACKER[ip].filter(
            timestamp => (currentTime - timestamp) <= THRESHOLD_WINDOW_MS
        );
        if (RECENT_ATTACK_TRACKER[ip].length === 0) {
            delete RECENT_ATTACK_TRACKER[ip];
        }
    }
}, 5 * 60 * 1000);

// --- API ENDPOINTS ---

// Endpoint 6: Health Check
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'ok', timestamp: new Date() });
});


// Endpoint 1: Get Analysis for the Last 24 Hours
app.get('/reports/recent', async (req, res) => {
    try {
        const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
        const { data, error } = await supabase
            .from('network_flows')
            .select('*')
            .gte('created_at', twentyFourHoursAgo)
            .limit(10000);

        if (error) throw error;
        if (!data || data.length === 0) return res.json({ message: "No data found for the last 24 hours." });
        
        const finalDashboardData = transformPredictionData(data);
        res.json(finalDashboardData);
    } catch (error) {
        res.status(500).json({ error: `Failed to fetch recent report: ${error.message}` });
    }
});


// Endpoint 2: Get Analysis for a Custom Date Range
app.get('/reports/custom', async (req, res) => {
    const { start, end } = req.query; // e.g., ?start=2025-09-01&end=2025-09-05
    if (!start || !end) {
        return res.status(400).json({ error: 'Please provide both a "start" and "end" query parameter.' });
    }
    try {
        const { data, error } = await supabase
            .from('network_flows')
            .select('*')
            .gte('created_at', new Date(start).toISOString())
            .lte('created_at', new Date(end).toISOString())
            .limit(10000);

        if (error) throw error;
        if (!data || data.length === 0) {
            return res.json({ message: "No data found for the specified date range." });
        }
        console.log(data.length);
        const finalDashboardData = transformPredictionData(data);
        res.json(finalDashboardData);
    } catch (error) {
        res.status(500).json({ error: `Failed to fetch custom report: ${error.message}` });
    }
});


// Endpoint 3: Analyze a new CSV file
// Endpoint 3: Analyze a new CSV file
// Endpoint 3: Analyze a new CSV file
app.post('/analyze/csv', upload.single('csvfile'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No CSV file provided.' });
    }

    // ⭐ STEP 1: GENERATE UNIQUE JOB ID (Analysis ID)
    const jobId = uuidv4(); 
    console.log(`Starting CSV analysis job: ${jobId}`);
    
    try {
        // 🚨 CRITICAL FIX: Insert into the UNIQUE parent table (analysis_jobs) 🚨
        const { error: jobInsertError } = await supabase.from('analysis_jobs').insert({ analysis_id: jobId });
        if (jobInsertError) {
             console.error("CRITICAL JOB INSERTION ERROR:", jobInsertError.message);
             return res.status(500).json({ error: 'Failed to initialize analysis job in DB.' });
        }

        const csvString = req.file.buffer.toString('utf8');
        const { data: rows } = Papa.parse(csvString, { header: true, skipEmptyLines: true, dynamicTyping: true });

        if (rows.length === 0) {
            return res.json({ message: "No data found in the provided CSV file.", analysis_id: jobId });
        }

        const BATCH_SIZE = 100;
        const resultsWithPredictions = [];
        console.log(`Processing ${rows.length} rows in batches of ${BATCH_SIZE}...`);

        for (let i = 0; i < rows.length; i += BATCH_SIZE) {
            const batch = rows.slice(i, i + BATCH_SIZE);
            const batchForModel = batch.map(({ Timestamp, timestamp, ...rest }) => rest);
            
            try {
                const response = await axios.post(MODEL_API_URL_BATCH, batchForModel);
                const predictions = response.data.predictions;

                const batchWithPredictions = batch.map((row, index) => {
                    let prediction = predictions[index] || 'Error';
                    
                    // Diagnostic check: This will be false after testing
                    if (DIAGNOSTIC_FORCE_ATTACK && index === 0) {
                        prediction = 'Forced_DDoS_Test';
                    }
                    
                    const rowWithPrediction = { 
                        ...row, 
                        prediction,
                        analysis_id: jobId, // Link to the analysis job
                    };

                    // ⭐ DEFENSE RULE GENERATION
                    if (prediction !== 'benign' && prediction !== 'Error') {
                        // Use the new aggregation function (non-blocking)
                        manageDefenseRules(supabase, row, prediction, jobId);
                    }

                    return rowWithPrediction;
                });
                resultsWithPredictions.push(...batchWithPredictions);
                
            } catch (error) {
                console.error(`Error predicting batch starting at index ${i}:`, error.message);
                const errorBatch = batch.map(row => ({ ...row, prediction: 'Error', analysis_id: jobId }));
                resultsWithPredictions.push(...errorBatch);
            }
        }
        
        // ⭐ STEP 3: SAVE ALL RESULTS TO SUPABASE
        console.log("Saving all CSV analysis results to Supabase...");
        await saveAnalysisResults(supabase, jobId, resultsWithPredictions); 
        
        // 4. Transform the combined data for the dashboard
        const finalDashboardData = transformPredictionData(resultsWithPredictions);

        // 5. Send the final dashboard data AS WELL AS the analysis_id
        res.json({
            ...finalDashboardData, 
            analysis_id: jobId    
        });
        
    } catch (error) {
        console.error(`Failed to process CSV file: ${error.message}`);
        res.status(500).json({ error: `Failed to process CSV file: ${error.message}` });
    }
});


app.post('/analyze/api', async (req, res) => {
    const { apiUrl } = req.body;
    if (!apiUrl) {
        return res.status(400).json({ error: 'Missing "apiUrl" in request body.' });
    }

    // ⭐ STEP 1: GENERATE UNIQUE JOB ID (Analysis ID)
    const jobId = uuidv4(); 
    console.log(`Starting analysis job: ${jobId}`);

    try {
        // 🚨 CRITICAL FIX: Insert into the UNIQUE parent table (analysis_jobs) 🚨
        const { error: jobInsertError } = await supabase.from('analysis_jobs').insert({ analysis_id: jobId });
        if (jobInsertError) {
             console.error("CRITICAL JOB INSERTION ERROR:", jobInsertError.message);
             return res.status(500).json({ error: 'Failed to initialize analysis job in DB.' });
        }

        // 2. Fetch the data from the provided URL using axios
        console.log(`Fetching data from: ${apiUrl}`);
        const apiResponse = await axios.get(apiUrl);
        const rows = apiResponse.data;

        if (!Array.isArray(rows) || rows.length === 0) {
            return res.status(400).json({ error: 'No valid data found.' });
        }

        // 3. Process data in batches and get predictions
        const BATCH_SIZE = 100;
        const resultsWithPredictions = [];

        for (let i = 0; i < rows.length; i += BATCH_SIZE) {
            const batch = rows.slice(i, i + BATCH_SIZE);
            const batchForModel = batch.map(({ created_at, ...rest }) => rest);
            
            try {
                const modelResponse = await axios.post(MODEL_API_URL_BATCH, batchForModel);
                const predictions = modelResponse.data.predictions;

                const batchWithPredictions = batch.map((row, index) => {
                    let prediction = predictions[index] || 'Error';

                    if (DIAGNOSTIC_FORCE_ATTACK && index === 0) {
                        prediction = 'Forced_DDoS_Test';
                    }

                    const rowWithPrediction = { 
                        ...row, 
                        prediction,
                        analysis_id: jobId, // Link to the analysis job
                    };

                    // ⭐ DEFENSE RULE GENERATION
                    if (prediction !== 'benign' && prediction !== 'Error') {
                        manageDefenseRules(supabase, row, prediction, jobId);
                    }
                    
                    return rowWithPrediction;
                });

                resultsWithPredictions.push(...batchWithPredictions);

            } catch (error) {
                console.error(`Error predicting batch starting at index ${i}:`, error.message);
                const errorBatch = batch.map(row => ({ ...row, prediction: 'Error', analysis_id: jobId }));
                resultsWithPredictions.push(...errorBatch);
            }
        }
        
        // ⭐ STEP 3: SAVE ALL RESULTS TO SUPABASE
        console.log("Saving all analysis results to Supabase...");
        await saveAnalysisResults(supabase, jobId, resultsWithPredictions); 
        
        // 4. Transform the combined data for the dashboard
        const finalDashboardData = transformPredictionData(resultsWithPredictions);

        // 5. Send the final dashboard data as the response
        res.json({
            ...finalDashboardData, 
            analysis_id: jobId    
        });

    } catch (error) {
        console.error(`Failed to process API URL ${apiUrl}:`, error.message);
        res.status(500).json({ error: `Failed to fetch or process data from API: ${error.message}` });
    }
});

// ... (the rest of your server.js file) ...

// Endpoint 4: Ingest a single data row
app.post('/ingest/single', async (req, res) => {
    const row = req.body;
    if (!row || Object.keys(row).length === 0) {
        return res.status(400).json({ error: 'No data row provided in request body.' });
    }
    try {
        const { timestamp, ...rowForModel } = row;
        const response = await axios.post(MODEL_API_URL_SINGLE, rowForModel);
        const dataToInsert = { ...row, prediction: response.data.prediction };

        const { error } = await supabase.from('network_flows').insert(dataToInsert);
        if (error) throw error;

        res.status(201).json({ success: true, message: 'Data ingested and stored successfully.', data: dataToInsert });
    } catch (error) {
        res.status(500).json({ error: `Failed to ingest data: ${error.message}` });
    }
});


// Endpoint 5: Ingest a batch of data rows
app.post('/ingest/batch', async (req, res) => {
    const rows = req.body;
    if (!rows || !Array.isArray(rows) || rows.length === 0) {
        return res.status(400).json({ error: 'Request body must be a non-empty array of data rows.' });
    }
    try {
        const BATCH_SIZE = 100;
        const allDataToInsert = [];
        for (let i = 0; i < rows.length; i += BATCH_SIZE) {
            const batch = rows.slice(i, i + BATCH_SIZE);
            const batchForModel = batch.map(({ timestamp, ...rest }) => rest);
            try {
                const response = await axios.post(MODEL_API_URL_BATCH, batchForModel);
                const predictions = response.data.predictions;
                const batchWithPredictions = batch.map((row, index) => ({ ...row, prediction: predictions[index] || 'Error' }));
                allDataToInsert.push(...batchWithPredictions);
            } catch (error) {
                // If prediction fails for a batch, we'll still try to insert with 'Error' label
                const errorBatch = batch.map(row => ({ ...row, prediction: 'Error' }));
                allDataToInsert.push(...errorBatch);
            }
        }

        const { error } = await supabase.from('network_flows').insert(allDataToInsert);
        if (error) throw error;
        
        res.status(201).json({ success: true, message: `Successfully ingested and stored ${allDataToInsert.length} records.` });
    } catch (error) {
        res.status(500).json({ error: `Failed to ingest batch data: ${error.message}` });
    }
});



app.get('/reports/date-range', async (req, res) => {
    try {
        const { data, error } = await supabase.rpc('get_date_range');
        if (error) throw error;
        res.json(data[0]);
    } catch (error) {
        res.status(500).json({ error: `Failed to fetch date range: ${error.message}` });
    }
});


// Endpoint 7: Re-analyze historical data against current rules (FILTERING & RE-PREDICTION)
// Endpoint 7: Re-analyze historical data against current rules (FILTERING & RE-PREDICTION)
app.post('/reanalyze/rules', async (req, res) => {
    const { analysis_id } = req.body;
    if (!analysis_id) {
        return res.status(400).json({ error: 'Missing "analysis_id" in request body.' });
    }

    try {
        // 2. Retrieve ALL historical flow data for this analysis ID
        const historicalResults = await getAnalysisResultsByJobId(supabase, analysis_id);

        if (!historicalResults || historicalResults.length === 0) {
            return res.status(404).json({ error: `No historical data found for ID: ${analysis_id}` });
        }
        
        // 3. Retrieve all active rules (Simplified query after previous debugging)
        const { data: activeRules } = await supabase
            .from('defense_rules')
            .select('ip_address, created_at, expires_at') 
            .eq('is_active', true)
            .gt('expires_at', new Date().toISOString()); 

        console.log(`Fetched ${activeRules ? activeRules.length : 0} active defense rules from DB.`);
        // Create a fast lookup map for rule temporal data
        const blockedIpMap = {};
        if (activeRules) {
            activeRules.forEach(rule => {
                blockedIpMap[rule.ip_address] = {
                    created_at: new Date(rule.created_at).getTime(),
                    expires_at: new Date(rule.expires_at).getTime(),
                };
            });
        }
        
        // ... (The top part of the endpoint, Steps 1, 2, 3, and setup remain the same) ...

        console.log(`Starting filtration and re-prediction for job ID: ${analysis_id}`);
        console.log(`Found ${historicalResults.length} flows and ${Object.keys(blockedIpMap).length} active rules.`);

        // 4. FILTER ROWS (Capture both kept and blocked flows)
        const flowsToReanalyze = [];
        const blockedFlows = []; // 💡 NEW ARRAY TO CAPTURE BLOCKED ROWS

        historicalResults.forEach(row => {
            const historicalFlowTime = new Date(row.created_at).getTime();
            const originalPrediction = row.prediction ? row.prediction.toLowerCase() : 'error';

            const srcIpRule = blockedIpMap[row.src_ip];
            const dstIpRule = blockedIpMap[row.dst_ip];
            const ruleData = srcIpRule || dstIpRule;

            // 🛑 SIMPLIFICATION FIX: Assume rule is active if it exists (As you requested)
            const ruleWasActiveAtFlowTime = true; // Overridden for simplified testing

            const isBlockedByPolicy = ruleData && ruleWasActiveAtFlowTime && 
                                      originalPrediction !== 'benign' && originalPrediction !== 'error';

            if (isBlockedByPolicy) {
                // Flow was blocked. Add it to the blocked list.
                blockedFlows.push({
                    ...row, 
                    // 💡 Mark the prediction to easily identify it in the frontend
                    prediction: 'Rule_Blocked_Historical' 
                });
            } else {
                // Flow passed the filter. Add it to the list for re-prediction.
                flowsToReanalyze.push(row);
            }
        });

        console.log(`Blocked ${blockedFlows.length} flows. Filtered down to ${flowsToReanalyze.length} flows for re-prediction.`);
        
        if (flowsToReanalyze.length === 0) {
             return res.json({ message: "All flows were filtered by active rules.", analysis_id });
        }


        // 5. PREPARE AND RESEND ROWS TO THE MODEL FOR RECALCULATION
        // ... (This section runs the re-prediction on flowsToReanalyze, yielding rePredictionResults) ...
        const BATCH_SIZE = 100;
        const rePredictionResults = [];

        for (let i = 0; i < flowsToReanalyze.length; i += BATCH_SIZE) {
            const batch = flowsToReanalyze.slice(i, i + BATCH_SIZE);
            const batchForModel = batch.map(({ prediction, analysis_id, ...rest }) => rest);
            
            try {
                const response = await axios.post(MODEL_API_URL_BATCH, batchForModel);
                const predictions = response.data.predictions;

                const batchWithNewPredictions = batch.map((row, index) => ({
                    ...row, 
                    original_prediction: row.prediction, 
                    prediction: predictions[index] || 'Error',
                }));
                rePredictionResults.push(...batchWithNewPredictions);
                
            } catch (error) {
                 console.error(`Error re-predicting batch starting at index ${i}:`, error.message);
                 const errorBatch = batch.map(row => ({ ...row, original_prediction: row.prediction, prediction: row.prediction }));
                 rePredictionResults.push(...errorBatch);
            }
        }
        
        // 6. TRANSFORM AND SEND RESULTS
        console.log("Re-prediction complete. Transforming for dashboard...");
        
        // Transform the re-predicted set
        const finalDashboardData = transformPredictionData(rePredictionResults);

        // 💡 NEW: Transform the BLOCKED set using a new dedicated function
        const blockedDashboardData = transformBlockedData(blockedFlows);

        // Send the final dashboard data (with the new prediction values)
        res.json({
            ...finalDashboardData,
            analysis_id,
            original_flow_count: historicalResults.length,
            reanalyzed_flow_count: rePredictionResults.length,
            blockedData: blockedDashboardData, // 💡 NEW FIELD IN RESPONSE
        });

    } catch (error) {
        console.error(`Failed to process re-analysis for ID ${analysis_id}:`, error.message);
        res.status(500).json({ error: `Failed to re-analyze data: ${error.message}` });
    }
});

// --- START THE SERVER ---
app.listen(PORT, () => {
    console.log(`✅ Node.js backend listening on port ${PORT}`);
});