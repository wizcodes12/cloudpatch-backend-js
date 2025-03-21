import React, { useState, useRef, useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { Search, Loader, AlertTriangle, Check, Code, Download, X, Server, ArrowLeft } from 'lucide-react';
import '../styles/ManualCheck.css';
import authService from "../services/authService";

// Import ManualCheckLoader component
import ManualCheckLoader from './ManualCheckLoader';

const ManualCheck = ({ user, setUser, API_BASE_URL, showNotification }) => {
  const location = useLocation();
  const navigate = useNavigate();
  const [hostingType, setHostingType] = useState(null); // Will be set from location state
  const [apiUrl, setApiUrl] = useState("");
  const [protocol, setProtocol] = useState("http");
  const [method, setMethod] = useState("GET");
  const [port, setPort] = useState("3000");
  const [loading, setLoading] = useState(false);
  const [scanResults, setScanResults] = useState(null);
  const [applyingFix, setApplyingFix] = useState(false);
  const [generatingPDF, setGeneratingPDF] = useState(false);
  const [showPrompt, setShowPrompt] = useState(false);
  const [promptMessage, setPromptMessage] = useState("");
  const [promptType, setPromptType] = useState(""); // 'success' or 'error'
  const [showPopupBlocked, setShowPopupBlocked] = useState(false);
  const [showLoader, setShowLoader] = useState(false);
  const [loaderType, setLoaderType] = useState('scanning');

  const resultsRef = useRef(null);

  // Set hosting type from location state on component mount
  useEffect(() => {
    if (location.state && location.state.hostingType) {
      setHostingType(location.state.hostingType);
    } else {
      // Redirect back to choose page if no hosting type specified
      navigate('/choose');
    }
  }, [location, navigate]);

  // Process tokens from URL parameters (e.g., after GitHub OAuth redirect)
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get('token');
    
    if (token) {
      // Store token in multiple locations for redundancy
      localStorage.setItem("github_token", token);
      sessionStorage.setItem("github_token", token);
      
      // Clean up URL after processing
      const cleanUrl = window.location.pathname + 
                      (window.location.search.replace(/[?&]token=[^&]+/, '').replace(/^\?$/, ''));
      window.history.replaceState({}, document.title, cleanUrl);
      
      // If there's user data in the URL as well
      const userData = urlParams.get('user_data');
      if (userData) {
        try {
          const parsedUserData = JSON.parse(decodeURIComponent(userData));
          // Only use setUser if it's available as a prop
          if (typeof setUser === 'function') {
            setUser(parsedUserData);
          }
        } catch (e) {
          console.error("Failed to parse user data from URL", e);
        }
      }
      
      // Show success notification if available
      if (typeof showNotification === 'function') {
        showNotification("Successfully authenticated with GitHub", "success");
      }
    }
  }, [showNotification, setUser]); // Add dependencies

  const validateApiUrl = (url) => {
    if (hostingType === 'cloud') {
      try {
        const parsedUrl = new URL(url);
        return parsedUrl.protocol === 'http:' || parsedUrl.protocol === 'https:';
      } catch {
        return false;
      }
    }
    // For local endpoints, just check if there's any content
    return !!url.trim();
  };

  const scrollToResults = () => {
    if (resultsRef.current) {
      resultsRef.current.scrollIntoView({ behavior: 'smooth' });
    }
    setShowPrompt(false);
  };

  const displayPrompt = (message, type, autoHide = true) => {
    setPromptMessage(message);
    setPromptType(type);
    setShowPrompt(true);

    if (autoHide) {
      setTimeout(() => {
        setShowPrompt(false);
      }, 3000);
    }
  };

  // Helper function to get GitHub token from various sources
  const getGitHubToken = () => {
    // Try each source in sequence until we find a valid token
    // 1. First check user object
    if (user && user.token) {
      return user.token;
    }
    
    // 2. Try localStorage
    const localToken = localStorage.getItem("github_token");
    if (localToken) {
      return localToken;
    }
    
    // 3. Try sessionStorage
    const sessionToken = sessionStorage.getItem("github_token");
    if (sessionToken) {
      return sessionToken;
    }
    
    return null;
  };

  const handleBackToChoose = () => {
    navigate('/choose');
  };

  const handleAllowPopups = () => {
    setShowPopupBlocked(false);
    // Try to open a test popup to ensure they're allowed
    const testPopup = window.open('about:blank', '_blank', 'width=100,height=100');
    if (testPopup) {
      testPopup.close();
      // Continue with the fix after popups are allowed
      if (applyingFix) {
        handleAutoFix(lastErrorAttempted, lastSolutionAttempted);
      }
    }
  };

  const closeLoader = () => {
    setShowLoader(false);
  };

  // Store the last error/solution attempted for retry after popup blocked
  let lastErrorAttempted = null;
  let lastSolutionAttempted = null;

  const checkApi = async () => {
    if (!apiUrl) {
      displayPrompt("Please enter an API URL or endpoint", "error");
      return;
    }
  
    if (!validateApiUrl(apiUrl)) {
      displayPrompt(hostingType === 'cloud' ? "Please enter a valid full URL" : "Please enter a valid endpoint", "error");
      return;
    }
  
    try {
      setLoading(true);
      setShowLoader(true);
      setLoaderType('scanning');
      
      const token = authService.getGitHubToken(); // Use authService consistently
      
      // Prepare the API endpoint and query parameters
      let fullUrl = '';
      let requestUrl = '';
      
      if (hostingType === 'local') {
        // Clean the path of leading slashes, regardless of whether it contains "api" or not
        const cleanPath = apiUrl.replace(/^\/+/, '');
        fullUrl = `${protocol}://localhost:${port}/${cleanPath}`;
        requestUrl = `${API_BASE_URL}/check-api?api_url=${encodeURIComponent(cleanPath)}&method=${method}&port=${port}`;
      } else {
        // For cloud hosting, send the full URL
        fullUrl = apiUrl;
        requestUrl = `${API_BASE_URL}/check-api?api_url=${encodeURIComponent(fullUrl)}&method=${method}`;
      }
  
      console.log("Sending request to:", requestUrl);
      
      const checkResponse = await fetch(
        requestUrl,
        {
          method: 'GET',
          headers: {
            "Authorization": token ? `Bearer ${token}` : '',
            "Content-Type": "application/json",
            "Origin": window.location.origin // Add explicit Origin header
          },
          credentials: 'include', // Ensure cookies are sent
          mode: 'cors' // Explicitly request CORS mode
        }
      );
  
      if (!checkResponse.ok) {
        const errorText = await checkResponse.text();
        console.error("API response error:", errorText);
        throw new Error(`Error checking API: ${checkResponse.status} ${checkResponse.statusText} - ${errorText}`);
      }
      
      const apiCheckData = await checkResponse.json();
      console.log("API check response:", apiCheckData);
      
      // Check if the response indicates the server isn't running locally
      const isLocalServerError = 
        apiCheckData.error && 
        (apiCheckData.error.includes("Local server not running") || 
         apiCheckData.error.includes("Local API unreachable"));
      
      // Updated error detection logic
      const hasErrors = 
        apiCheckData.error || 
        apiCheckData.status === "error" ||
        (apiCheckData.scan_results?.errors_detected && 
         apiCheckData.scan_results.errors_detected.length > 0);
      
      // Process and prepare scan results
      setScanResults({
        ...apiCheckData,
        api_url: fullUrl,
        scan_results: {
          apis_found: [fullUrl],
          errors_detected: apiCheckData.error ? [{error: apiCheckData.error}] : 
                          (apiCheckData.scan_results?.errors_detected || []),
          solutions: apiCheckData.solution ? [{solution: apiCheckData.solution}] : 
                    (apiCheckData.scan_results?.solutions || [])
        },
        // Add a flag that directly indicates if this is a local server error
        is_local_server_error: isLocalServerError,
        // Keep track of whether this was a local endpoint check
        is_local: hostingType === 'local'
      });
  
      const errorCount = apiCheckData.error ? 1 : 
                        (apiCheckData.scan_results?.errors_detected?.length || 0);
  
      if (isLocalServerError) {
        // Special handling for local server errors
        displayPrompt(
          "Local server is not running. Please start your local server first.",
          "error",
          false // Don't auto-hide
        );
      } else if (hasErrors) {
        displayPrompt(
          `${errorCount} issue${errorCount !== 1 ? 's' : ''} found with your API`,
          "error",
          false // Don't auto-hide
        );
      } else {
        displayPrompt("API check completed successfully", "success");
      }
    } catch (error) {
      console.error("API check error:", error);
      displayPrompt(error.message || "Failed to check API", "error");
      setScanResults({
        error: error.message || "Failed to check API",
        status: "error",
        api_url: hostingType === 'local' ? `${protocol}://localhost:${port}/${apiUrl.replace(/^\/+/, '')}` : apiUrl,
        scan_results: {
          apis_found: [hostingType === 'local' ? `${protocol}://localhost:${port}/${apiUrl.replace(/^\/+/, '')}` : apiUrl],
          errors_detected: [{error: error.message || "Failed to check API"}],
          solutions: []
        },
        is_local: hostingType === 'local'
      });
    } finally {
      setLoading(false);
      setShowLoader(false);
    }
  };

  // Auto-fix function
  // Auto-fix function
const handleAutoFix = async (error, solution) => {
  // Store the error and solution for potential retry
  lastErrorAttempted = error;
  lastSolutionAttempted = solution;
  
  try {
    setApplyingFix(true);
    setShowLoader(true);
    setLoaderType('applying-fix');
    
    // Get the GitHub token directly from AuthService
    const token = authService.getGitHubToken();
    if (!token) {
      displayPrompt("GitHub token not found. Please log in again.", "error");
      
      // Direct to login page using authService
      authService.redirectToLogin(window.location.href, 'web');
      return;
    }
    
    console.log("Using token for auto-fix:", token.substring(0, 5) + "...");
    
    // Call your server's /apply-fix endpoint to get the DeepSeek solution
    const response = await fetch(`${API_BASE_URL}/apply-fix`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
        "Origin": window.location.origin
      },
      body: JSON.stringify({
        api_url: apiUrl,
        fix_content: error.error
      }),
      credentials: 'include',
      mode: 'cors'
    });
    
    if (!response.ok) {
      let errorData;
      try {
        errorData = await response.json();
      } catch (e) {
        // If JSON parsing fails, get the response as text
        const text = await response.text();
        errorData = { detail: text };
      }
      
      console.error("Apply fix error response:", errorData);
      throw new Error(`Failed to prepare fix: ${typeof errorData === 'object' ? JSON.stringify(errorData) : errorData}`);
    }
    
    const result = await response.json();
    console.log("Apply fix response:", result);
    
    if (result.status === "auth_required") {
      // Open a new window for GitHub authentication
      const width = 1000;
      const height = 800;
      const left = window.screenX + (window.outerWidth - width) / 2;
      const top = window.screenY + (window.outerHeight - height) / 2;
      
      const popupWindow = window.open(
        result.auth_url,
        'github-auth',
        `width=${width},height=${height},left=${left},top=${top},resizable=yes,scrollbars=yes,status=yes`
      );
      
      if (!popupWindow) {
        setShowPopupBlocked(true);
        displayPrompt("Popup was blocked. Please allow popups for this site.", "error");
        return;
      }
      
      // Set up event listener for messages from the popup
      const messageHandler = function(event) {
        // Check if message is from our expected origin
        const expectedOrigins = [
          'http://localhost:3000',
          'http://localhost:8000', 
          'https://cloudpatch-frontend.onrender.com',
          API_BASE_URL
        ];
        
        if (!expectedOrigins.includes(event.origin) && !event.origin.includes('localhost')) {
          console.warn(`Ignoring message from unexpected origin: ${event.origin}`);
          return;
        }
        
        if (event.data && event.data.type === 'auth_complete') {
          // Handle successful authentication
          console.log("Received auth_complete message", event.data);
          
          // Store the new token if provided
          if (event.data.token) {
            authService.storeGitHubToken(event.data.token, event.data.user);
          }
          
          displayPrompt("Authentication successful! Please try applying the fix again.", "success");
          checkApi(); // Refresh results
        }
      };
      
      window.addEventListener('message', messageHandler);
      
      // Clean up event listener when window closes
      const checkPopupClosed = setInterval(() => {
        if (popupWindow.closed) {
          clearInterval(checkPopupClosed);
          window.removeEventListener('message', messageHandler);
        }
      }, 1000);
      
      return;
    }
    
    if (!result.solution) {
      throw new Error("No solution was generated");
    }
    
    // Create issue body with the solution
    const issueBody = `## Error Detected\n${error.error}\n\n## Suggested Fix\n\`\`\`javascript\n${result.solution}\n\`\`\`\n\nGenerated by API Fixer tool`;
    const issueTitle = `Fix for API issue: ${apiUrl}`;
    
    // Use a server-side endpoint to handle the GitHub issue creation window
    const width = 1000;
    const height = 800;
    const left = window.screenX + (window.outerWidth - width) / 2;
    const top = window.screenY + (window.outerHeight - height) / 2;
    
    // Use the github-issue-creator endpoint to open a new window
    const creatorUrl = `${API_BASE_URL}/github-issue-creator?token=${encodeURIComponent(token)}&title=${encodeURIComponent(issueTitle)}&body=${encodeURIComponent(issueBody)}`;
    
    const popupWindow = window.open(
      creatorUrl,
      'github-issue-creator',
      `width=${width},height=${height},left=${left},top=${top},resizable=yes,scrollbars=yes,status=yes`
    );
    
    if (!popupWindow) {
      setShowPopupBlocked(true);
      displayPrompt("Popup was blocked. Please allow popups for this site.", "error");
      return;
    }
    
    // Set up event listener for messages from the popup
    const messageHandler = function(event) {
      // Check if message is from our expected origin
      const expectedOrigins = [
        'http://localhost:3000',
        'http://localhost:8000', 
        'https://cloudpatch-frontend.onrender.com',
        API_BASE_URL
      ];
      
      if (!expectedOrigins.includes(event.origin) && !event.origin.includes('localhost')) {
        console.warn(`Ignoring message from unexpected origin: ${event.origin}`);
        return;
      }
      
      if (event.data && event.data.type === 'issue-created') {
        displayPrompt(`Issue #${event.data.issueNumber} created successfully!`, "success");
        checkApi(); // Refresh results
      }
    };
    
    window.addEventListener('message', messageHandler);
    
    // Clean up event listener when window closes
    const checkPopupClosed = setInterval(() => {
      if (popupWindow.closed) {
        clearInterval(checkPopupClosed);
        window.removeEventListener('message', messageHandler);
      }
    }, 1000);
    
    displayPrompt("GitHub repository selector opened in new window", "success");
  } catch (error) {
    console.error("Auto-fix error:", error);
    displayPrompt(error.message || "Failed to apply fix", "error");
  } finally {
    setApplyingFix(false);
    setShowLoader(false);
  }
};

  const handleDownloadPDF = async (error, solution, apiDetails) => {
    try {
      setGeneratingPDF(true);
      setShowLoader(true);
      setLoaderType('generating-pdf');
      
      const token = getGitHubToken();
      
      const reportData = {
        timestamp: new Date().toISOString(),
        api_url: apiDetails.api_url,
        platform: apiDetails.platform || 'Unknown',
        error: {
          type: 'API Error',
          message: error.error || 'Unknown error',
          severity: 'HIGH',
          timestamp: new Date().toISOString()
        },
        solution: {
          description: solution?.solution || 'No solution available',
          suggested_fixes: []
        },
        additional_context: {
          environment: apiDetails.environment || 'Production',
          performance_metrics: apiDetails.performance_metrics || {},
          status_code: apiDetails.status_code || 500
        }
      };

      if (!reportData.api_url || !reportData.error.message) {
        throw new Error('Missing required data for PDF generation');
      }

      const response = await fetch(`${API_BASE_URL}/api/generate-pdf-report`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(reportData)
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail?.message || 'Failed to generate PDF report');
      }

      const contentDisposition = response.headers.get('Content-Disposition');
      const filename = contentDisposition
        ? contentDisposition.split('filename=')[1].replace(/"/g, '')
        : `api-error-report-${new Date().toISOString()}.pdf`;

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.style.display = 'none';
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      
      displayPrompt("Report downloaded successfully!", "success");
    } catch (error) {
      console.error('Error downloading PDF:', error);
      displayPrompt(error.message || "Failed to generate PDF report", "error");
    } finally {
      setGeneratingPDF(false);
      setShowLoader(false);
    }
  };

  const renderLocalServerError = () => (
    <div className="local-server-error">
      <div className="error-icon-container">
        <Server className="icon server-error-icon" />
        <AlertTriangle className="icon overlay-error-icon" />
      </div>
      <h3>Local Server Not Running</h3>
      <p>
        We couldn't connect to your local server at <strong>localhost:{port}</strong>. 
        Please make sure your server is running before checking the API.
      </p>
      <div className="server-error-tips">
        <h4>Troubleshooting Tips:</h4>
        <ul>
          <li>Check if your server is running with the correct command (e.g., <code>npm start</code> or <code>npm run dev</code>)</li>
          <li>Verify that your server is using port {port} (check your server configuration)</li>
          <li>Make sure no firewall is blocking connections to port {port}</li>
          <li>Try restarting your development server</li>
        </ul>
      </div>
      <button className="retry-button" onClick={checkApi}>
        <Search className="icon" />
        <span>Retry Scan</span>
      </button>
    </div>
  );

  const DownloadButton = ({ error, solution, isLoading, apiDetails }) => (
    <button
      onClick={() => handleDownloadPDF(error, solution, apiDetails)}
      disabled={isLoading}
      className="download-button"
    >
      <span className="button-text">
        {isLoading ? 'Generating Report...' : 'Download Report'}
      </span>
      {isLoading ? (
        <Loader className="icon-spin" />
      ) : (
        <Download className="icon" />
      )}
    </button>
  );

  // If hosting type not yet set, show loading
  if (hostingType === null) {
    return (
      <div className="manual-check loading-state">
        <Loader className="icon-spin" size={48} />
        <p>Loading...</p>
      </div>
    );
  }

  // Render main API check interface
  return (
    <div className="manual-check">
      {showPrompt && (
        <div className={`notification-prompt ${promptType}`}>
          <div className="prompt-content">
            <span className="prompt-message">
              {promptType === "error" ? <AlertTriangle className="prompt-icon" /> : <Check className="prompt-icon" />}
              {promptMessage}
            </span>
            <div className="prompt-actions">
              {promptType === "error" && scanResults && (
                <button className="show-button" onClick={scrollToResults}>
                  Show
                </button>
              )}
              <button className="cancel-button" onClick={() => setShowPrompt(false)}>
                <X className="cancel-icon" />
              </button>
            </div>
          </div>
        </div>
      )}
      
      {/* ManualCheckLoader overlay */}
      {showLoader && (
        <ManualCheckLoader 
          type={loaderType}
          onClose={closeLoader}
          showPopupBlocked={showPopupBlocked}
          onAllowPopups={handleAllowPopups}
        />
      )}

      <div className="check-container">
        {/* <div className="back-link">
          <button className="back-button" onClick={handleBackToChoose}>
            <ArrowLeft className="icon" />
            <span>Back to Selection</span>
          </button>
        </div> */}

        <div className="manual-header">
          <h1>Manual API Check - {hostingType === 'local' ? 'Local Hosted' : 'Cloud Hosted'}</h1>
          <p>Enter {hostingType === 'local' ? 'any endpoint' : 'URL'} to scan for potential issues</p>
        </div>

        <div className="input-section">
          {hostingType === 'local' && (
            <div className="protocol-method-container">
              <select
                className="input-field select-field"
                value={protocol}
                onChange={(e) => setProtocol(e.target.value)}
              >
                <option value="http">HTTP</option>
                <option value="https">HTTPS</option>
              </select>

              <input
                type="number"
                className="input-field port-field"
                placeholder="Port (e.g., 3000)"
                value={port}
                onChange={(e) => setPort(e.target.value)}
                min="1"
                max="65535"
              />

              <select
                className="input-field select-field"
                value={method}
                onChange={(e) => setMethod(e.target.value)}
              >
                <option value="GET">GET</option>
                <option value="POST">POST</option>
                <option value="PUT">PUT</option>
                <option value="DELETE">DELETE</option>
              </select>
            </div>
          )}
          
          <input
            type="text"
            className="input-field api-field"
            placeholder={hostingType === 'local' ? "Enter endpoint (e.g., users/profile, auth/login)" : "Enter full URL (e.g., https://api.example.com/endpoint)"}
            value={apiUrl}
            onChange={(e) => setApiUrl(e.target.value)}
          />
          
          <button
            className="check-button"
            onClick={checkApi}
            disabled={loading}
          >
            {loading ? <Loader className="icon-spin" /> : <Search className="icon" />}
            <span>{loading ? "Scanning..." : "Scan API"}</span>
          </button>
        </div>

        {scanResults && (
          <div className="result-card" ref={resultsRef}>
            <div className="result-header">
              <h2>Scan Results</h2>
              {scanResults.is_local_server_error ? (
                <div className="status error">
                  <Server className="icon" />
                  Local Server Error
                </div>
              ) : scanResults.scan_results?.errors_detected?.length > 0 ? (
                <div className="status error">
                  <AlertTriangle className="icon" />
                  {scanResults.scan_results.errors_detected.length} Issues Found
                </div>
              ) : (
                <div className="status success">
                  <Check className="icon" />
                  API Healthy
                </div>
              )}
            </div>

            <div className="result-content">
              {/* Special UI for local server not running */}
              {scanResults.is_local_server_error ? (
                renderLocalServerError()
              ) : (
                <>
                  <div className="info-card platform-info">
                    <Code className="info-icon" />
                    <div className="info-text">
                      <h3 className="info-title">Platform</h3>
                      <p className="info-value">{scanResults.platform || 'Unknown'}</p>
                    </div>
                  </div>

                  <div className="info-card api-details">
                    <div className="info-text">
                      <h3 className="info-title">API Details</h3>
                      <p className="info-value api-url">{scanResults.api_url}</p>
                    </div>
                  </div>

                  {scanResults.scan_results?.errors_detected?.map((error, index) => (
                    <div key={index} className="error-card">
                      <div className="error-message">
                        <h3><AlertTriangle className="icon error-icon" /> Issue {index + 1}</h3>
                        <p>{error.error}</p>
                      </div>
                      
                      <DownloadButton
                        error={error}
                        solution={scanResults.scan_results.solutions[index]}
                        apiDetails={{
                          api_url: scanResults.api_url,
                          platform: scanResults.platform,
                          status_code: scanResults.status_code,
                          environment: scanResults.environment,
                          performance_metrics: scanResults.additional_info?.performance_metrics
                        }}
                        isLoading={generatingPDF}
                      />

                      {scanResults.scan_results.solutions[index] && (
                        <div className="solution-section">
                          <h3 className="solution-title">Suggested Fix</h3>
                          <pre className="solution-code">
                            <code>
                              {scanResults.scan_results.solutions[index].solution}
                            </code>
                          </pre>
                          <button 
                            onClick={() => handleAutoFix(error, scanResults.scan_results.solutions[index].solution)}
                            disabled={applyingFix || scanResults.is_local}
                            className="fix-button"
                          >
                            {applyingFix ? (
                              <>
                                <Loader className="icon-spin" />
                                <span>Applying Fix...</span>
                              </>
                            ) : (
                              <>
                                <Check className="icon" />
                                <span>Apply Fix</span>
                              </>
                            )}
                          </button>
                          {scanResults.is_local && (
                            <div className="local-fix-notice">
                              <AlertTriangle className="icon" />
                              <span>Auto-fix unavailable for local endpoints</span>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  ))}

                  {scanResults.error && !scanResults.scan_results?.errors_detected?.length && (
                    <div className="error-card general-error">
                      <div className="error-message">
                        <h3><AlertTriangle className="icon error-icon" /> General Issue</h3>
                        <p>{scanResults.error}</p>
                      </div>
                      {scanResults.solution && (
                        <div className="solution-section">
                          <h3 className="solution-title">Suggested Solution</h3>
                          <p>{scanResults.solution}</p>
                        </div>
                      )}
                    </div>
                  )}
                </>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ManualCheck;
