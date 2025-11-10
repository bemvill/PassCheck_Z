import { ConnectButton } from '@rainbow-me/rainbowkit';
import '@rainbow-me/rainbowkit/styles.css';
import React, { useEffect, useState } from "react";
import { getContractReadOnly, getContractWithSigner } from "./components/useContract";
import "./App.css";
import { useAccount } from 'wagmi';
import { useFhevm, useEncrypt, useDecrypt } from '../fhevm-sdk/src';
import { ethers } from 'ethers';

interface PasswordData {
  id: number;
  name: string;
  encryptedValue: string;
  strengthScore: number;
  leakRisk: number;
  timestamp: number;
  creator: string;
  publicValue1: number;
  publicValue2: number;
  isVerified?: boolean;
  decryptedValue?: number;
  encryptedValueHandle?: string;
}

interface PasswordStats {
  totalChecks: number;
  highStrength: number;
  mediumRisk: number;
  averageScore: number;
  recentChecks: number;
}

const App: React.FC = () => {
  const { address, isConnected } = useAccount();
  const [loading, setLoading] = useState(true);
  const [passwords, setPasswords] = useState<PasswordData[]>([]);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [creatingPassword, setCreatingPassword] = useState(false);
  const [transactionStatus, setTransactionStatus] = useState<{ visible: boolean; status: "pending" | "success" | "error"; message: string; }>({ 
    visible: false, 
    status: "pending" as const, 
    message: "" 
  });
  const [newPasswordData, setNewPasswordData] = useState({ name: "", password: "" });
  const [selectedPassword, setSelectedPassword] = useState<PasswordData | null>(null);
  const [decryptedData, setDecryptedData] = useState<number | null>(null);
  const [isDecrypting, setIsDecrypting] = useState(false);
  const [contractAddress, setContractAddress] = useState("");
  const [fhevmInitializing, setFhevmInitializing] = useState(false);
  const [searchTerm, setSearchTerm] = useState("");
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 5;

  const { status, initialize, isInitialized } = useFhevm();
  const { encrypt, isEncrypting} = useEncrypt();
  const { verifyDecryption, isDecrypting: fheIsDecrypting } = useDecrypt();

  useEffect(() => {
    const initFhevmAfterConnection = async () => {
      if (!isConnected) return;
      if (isInitialized) return;
      if (fhevmInitializing) return;
      
      try {
        setFhevmInitializing(true);
        console.log('Initializing FHEVM for password strength check...');
        await initialize();
        console.log('FHEVM initialized successfully');
      } catch (error) {
        console.error('Failed to initialize FHEVM:', error);
        setTransactionStatus({ 
          visible: true, 
          status: "error", 
          message: "FHEVM initialization failed" 
        });
        setTimeout(() => setTransactionStatus({ visible: false, status: "pending", message: "" }), 3000);
      } finally {
        setFhevmInitializing(false);
      }
    };

    initFhevmAfterConnection();
  }, [isConnected, isInitialized, initialize, fhevmInitializing]);

  useEffect(() => {
    const loadDataAndContract = async () => {
      if (!isConnected) {
        setLoading(false);
        return;
      }
      
      try {
        await loadData();
        const contract = await getContractReadOnly();
        if (contract) setContractAddress(await contract.getAddress());
      } catch (error) {
        console.error('Failed to load data:', error);
      } finally {
        setLoading(false);
      }
    };

    loadDataAndContract();
  }, [isConnected]);

  const loadData = async () => {
    if (!isConnected) return;
    
    setIsRefreshing(true);
    try {
      const contract = await getContractReadOnly();
      if (!contract) return;
      
      const businessIds = await contract.getAllBusinessIds();
      const passwordsList: PasswordData[] = [];
      
      for (const businessId of businessIds) {
        try {
          const businessData = await contract.getBusinessData(businessId);
          passwordsList.push({
            id: parseInt(businessId.replace('password-', '')) || Date.now(),
            name: businessData.name,
            encryptedValue: businessId,
            strengthScore: Number(businessData.publicValue1) || 0,
            leakRisk: Number(businessData.publicValue2) || 0,
            timestamp: Number(businessData.timestamp),
            creator: businessData.creator,
            publicValue1: Number(businessData.publicValue1) || 0,
            publicValue2: Number(businessData.publicValue2) || 0,
            isVerified: businessData.isVerified,
            decryptedValue: Number(businessData.decryptedValue) || 0
          });
        } catch (e) {
          console.error('Error loading password data:', e);
        }
      }
      
      setPasswords(passwordsList);
    } catch (e) {
      setTransactionStatus({ visible: true, status: "error", message: "Failed to load password data" });
      setTimeout(() => setTransactionStatus({ visible: false, status: "pending", message: "" }), 3000);
    } finally { 
      setIsRefreshing(false); 
    }
  };

  const calculatePasswordStrength = (password: string) => {
    let score = 0;
    if (password.length >= 8) score += 25;
    if (password.length >= 12) score += 15;
    if (/[A-Z]/.test(password)) score += 15;
    if (/[a-z]/.test(password)) score += 15;
    if (/[0-9]/.test(password)) score += 15;
    if (/[^A-Za-z0-9]/.test(password)) score += 15;
    
    const leakRisk = Math.max(5, 100 - score);
    
    return { strength: Math.min(100, score), risk: leakRisk };
  };

  const createPasswordCheck = async () => {
    if (!isConnected || !address) { 
      setTransactionStatus({ visible: true, status: "error", message: "Please connect wallet first" });
      setTimeout(() => setTransactionStatus({ visible: false, status: "pending", message: "" }), 3000);
      return; 
    }
    
    setCreatingPassword(true);
    setTransactionStatus({ visible: true, status: "pending", message: "Encrypting password with Zama FHE..." });
    
    try {
      const contract = await getContractWithSigner();
      if (!contract) throw new Error("Failed to get contract with signer");
      
      const { strength, risk } = calculatePasswordStrength(newPasswordData.password);
      const passwordLength = newPasswordData.password.length;
      const businessId = `password-${Date.now()}`;
      
      const encryptedResult = await encrypt(contractAddress, address, passwordLength);
      
      const tx = await contract.createBusinessData(
        businessId,
        newPasswordData.name,
        encryptedResult.encryptedData,
        encryptedResult.proof,
        strength,
        risk,
        "Password Strength Check"
      );
      
      setTransactionStatus({ visible: true, status: "pending", message: "Waiting for transaction confirmation..." });
      await tx.wait();
      
      setTransactionStatus({ visible: true, status: "success", message: "Password check created successfully!" });
      setTimeout(() => {
        setTransactionStatus({ visible: false, status: "pending", message: "" });
      }, 2000);
      
      await loadData();
      setShowCreateModal(false);
      setNewPasswordData({ name: "", password: "" });
    } catch (e: any) {
      const errorMessage = e.message?.includes("user rejected transaction") 
        ? "Transaction rejected by user" 
        : "Submission failed: " + (e.message || "Unknown error");
      setTransactionStatus({ visible: true, status: "error", message: errorMessage });
      setTimeout(() => setTransactionStatus({ visible: false, status: "pending", message: "" }), 3000);
    } finally { 
      setCreatingPassword(false); 
    }
  };

  const decryptData = async (businessId: string): Promise<number | null> => {
    if (!isConnected || !address) { 
      setTransactionStatus({ visible: true, status: "error", message: "Please connect wallet first" });
      setTimeout(() => setTransactionStatus({ visible: false, status: "pending", message: "" }), 3000);
      return null; 
    }
    
    setIsDecrypting(true);
    try {
      const contractRead = await getContractReadOnly();
      if (!contractRead) return null;
      
      const businessData = await contractRead.getBusinessData(businessId);
      if (businessData.isVerified) {
        const storedValue = Number(businessData.decryptedValue) || 0;
        
        setTransactionStatus({ 
          visible: true, 
          status: "success", 
          message: "Password length already verified on-chain" 
        });
        setTimeout(() => {
          setTransactionStatus({ visible: false, status: "pending", message: "" });
        }, 2000);
        
        return storedValue;
      }
      
      const contractWrite = await getContractWithSigner();
      if (!contractWrite) return null;
      
      const encryptedValueHandle = await contractRead.getEncryptedValue(businessId);
      
      const result = await verifyDecryption(
        [encryptedValueHandle],
        contractAddress,
        (abiEncodedClearValues: string, decryptionProof: string) => 
          contractWrite.verifyDecryption(businessId, abiEncodedClearValues, decryptionProof)
      );
      
      setTransactionStatus({ visible: true, status: "pending", message: "Verifying decryption on-chain..." });
      
      const clearValue = result.decryptionResult.clearValues[encryptedValueHandle];
      
      await loadData();
      
      setTransactionStatus({ visible: true, status: "success", message: "Password length decrypted and verified!" });
      setTimeout(() => {
        setTransactionStatus({ visible: false, status: "pending", message: "" });
      }, 2000);
      
      return Number(clearValue);
      
    } catch (e: any) { 
      if (e.message?.includes("Data already verified")) {
        setTransactionStatus({ 
          visible: true, 
          status: "success", 
          message: "Password length is already verified" 
        });
        setTimeout(() => {
          setTransactionStatus({ visible: false, status: "pending", message: "" });
        }, 2000);
        
        await loadData();
        return null;
      }
      
      setTransactionStatus({ 
        visible: true, 
        status: "error", 
        message: "Decryption failed: " + (e.message || "Unknown error") 
      });
      setTimeout(() => setTransactionStatus({ visible: false, status: "pending", message: "" }), 3000);
      return null; 
    } finally { 
      setIsDecrypting(false); 
    }
  };

  const testAvailability = async () => {
    try {
      const contract = await getContractReadOnly();
      if (!contract) return;
      
      const isAvailable = await contract.isAvailable();
      if (isAvailable) {
        setTransactionStatus({ visible: true, status: "success", message: "FHE system is available and ready!" });
        setTimeout(() => setTransactionStatus({ visible: false, status: "pending", message: "" }), 2000);
      }
    } catch (e) {
      setTransactionStatus({ visible: true, status: "error", message: "Availability check failed" });
      setTimeout(() => setTransactionStatus({ visible: false, status: "pending", message: "" }), 3000);
    }
  };

  const getPasswordStats = (): PasswordStats => {
    const totalChecks = passwords.length;
    const highStrength = passwords.filter(p => p.strengthScore >= 80).length;
    const mediumRisk = passwords.filter(p => p.leakRisk >= 50).length;
    const averageScore = totalChecks > 0 ? passwords.reduce((sum, p) => sum + p.strengthScore, 0) / totalChecks : 0;
    const recentChecks = passwords.filter(p => Date.now()/1000 - p.timestamp < 60 * 60 * 24).length;

    return { totalChecks, highStrength, mediumRisk, averageScore, recentChecks };
  };

  const filteredPasswords = passwords.filter(password => 
    password.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    password.creator.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const paginatedPasswords = filteredPasswords.slice(
    (currentPage - 1) * itemsPerPage,
    currentPage * itemsPerPage
  );

  const totalPages = Math.ceil(filteredPasswords.length / itemsPerPage);

  const renderStats = () => {
    const stats = getPasswordStats();
    
    return (
      <div className="stats-grid">
        <div className="stat-card neon-purple">
          <h3>Total Checks</h3>
          <div className="stat-value">{stats.totalChecks}</div>
          <div className="stat-trend">+{stats.recentChecks} today</div>
        </div>
        
        <div className="stat-card neon-blue">
          <h3>High Strength</h3>
          <div className="stat-value">{stats.highStrength}</div>
          <div className="stat-trend">Secure passwords</div>
        </div>
        
        <div className="stat-card neon-pink">
          <h3>Avg Score</h3>
          <div className="stat-value">{stats.averageScore.toFixed(1)}</div>
          <div className="stat-trend">Overall strength</div>
        </div>
        
        <div className="stat-card neon-green">
          <h3>Medium Risk</h3>
          <div className="stat-value">{stats.mediumRisk}</div>
          <div className="stat-trend">Need improvement</div>
        </div>
      </div>
    );
  };

  const renderStrengthBar = (strength: number) => {
    let color = "#ff4444";
    let label = "Weak";
    
    if (strength >= 80) {
      color = "#44ff44";
      label = "Strong";
    } else if (strength >= 60) {
      color = "#ffff44";
      label = "Good";
    } else if (strength >= 40) {
      color = "#ffaa44";
      label = "Fair";
    }
    
    return (
      <div className="strength-bar-container">
        <div className="strength-bar">
          <div 
            className="strength-fill" 
            style={{ width: `${strength}%`, backgroundColor: color }}
          ></div>
        </div>
        <span className="strength-label">{label} ({strength})</span>
      </div>
    );
  };

  const renderFHEFlow = () => {
    return (
      <div className="fhe-flow">
        <div className="flow-step">
          <div className="step-icon">1</div>
          <div className="step-content">
            <h4>Password Length Encryption</h4>
            <p>Password length encrypted with Zama FHE 🔐</p>
          </div>
        </div>
        <div className="flow-arrow">→</div>
        <div className="flow-step">
          <div className="step-icon">2</div>
          <div className="step-content">
            <h4>On-chain Storage</h4>
            <p>Encrypted length stored securely on blockchain</p>
          </div>
        </div>
        <div className="flow-arrow">→</div>
        <div className="flow-step">
          <div className="step-icon">3</div>
          <div className="step-content">
            <h4>Client-side Analysis</h4>
            <p>Strength calculated without exposing password</p>
          </div>
        </div>
        <div className="flow-arrow">→</div>
        <div className="flow-step">
          <div className="step-icon">4</div>
          <div className="step-content">
            <h4>Optional Verification</h4>
            <p>Verify decryption proof on-chain</p>
          </div>
        </div>
      </div>
    );
  };

  if (!isConnected) {
    return (
      <div className="app-container">
        <header className="app-header">
          <div className="logo">
            <h1>FHE Password Checker 🔐</h1>
          </div>
          <div className="header-actions">
            <div className="wallet-connect-wrapper">
              <ConnectButton accountStatus="address" chainStatus="icon" showBalance={false}/>
            </div>
          </div>
        </header>
        
        <div className="connection-prompt">
          <div className="connection-content">
            <div className="connection-icon">🔐</div>
            <h2>Connect Wallet to Start</h2>
            <p>Secure password strength checking with Fully Homomorphic Encryption</p>
            <div className="connection-steps">
              <div className="step">
                <span>1</span>
                <p>Connect your wallet to initialize FHE system</p>
              </div>
              <div className="step">
                <span>2</span>
                <p>Check password strength without exposing your data</p>
              </div>
              <div className="step">
                <span>3</span>
                <p>All processing happens encrypted with Zama FHE</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (!isInitialized || fhevmInitializing) {
    return (
      <div className="loading-screen">
        <div className="fhe-spinner"></div>
        <p>Initializing FHE Encryption System...</p>
        <p className="loading-note">Securing password analysis</p>
      </div>
    );
  }

  if (loading) return (
    <div className="loading-screen">
      <div className="fhe-spinner"></div>
      <p>Loading encrypted password system...</p>
    </div>
  );

  return (
    <div className="app-container">
      <header className="app-header">
        <div className="logo">
          <h1>FHE Password Checker 🔐</h1>
        </div>
        
        <div className="header-actions">
          <button onClick={testAvailability} className="test-btn">
            Test FHE
          </button>
          <button 
            onClick={() => setShowCreateModal(true)} 
            className="create-btn"
          >
            + Check Password
          </button>
          <div className="wallet-connect-wrapper">
            <ConnectButton accountStatus="address" chainStatus="icon" showBalance={false}/>
          </div>
        </div>
      </header>
      
      <div className="main-content">
        <section className="intro-section">
          <h2>Privacy-First Password Strength Analysis</h2>
          <p>Check password strength using Fully Homomorphic Encryption. Your passwords never leave your device unencrypted.</p>
          {renderFHEFlow()}
        </section>
        
        <section className="stats-section">
          <h2>Password Statistics</h2>
          {renderStats()}
        </section>
        
        <section className="passwords-section">
          <div className="section-header">
            <h2>Password Checks</h2>
            <div className="header-controls">
              <div className="search-box">
                <input 
                  type="text" 
                  placeholder="Search passwords..." 
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                />
              </div>
              <button 
                onClick={loadData} 
                className="refresh-btn" 
                disabled={isRefreshing}
              >
                {isRefreshing ? "Refreshing..." : "Refresh"}
              </button>
            </div>
          </div>
          
          <div className="passwords-list">
            {paginatedPasswords.length === 0 ? (
              <div className="no-passwords">
                <p>No password checks found</p>
                <button 
                  className="create-btn" 
                  onClick={() => setShowCreateModal(true)}
                >
                  Check First Password
                </button>
              </div>
            ) : paginatedPasswords.map((password, index) => (
              <div 
                className={`password-card ${selectedPassword?.id === password.id ? "selected" : ""} ${password.isVerified ? "verified" : ""}`} 
                key={index}
                onClick={() => setSelectedPassword(password)}
              >
                <div className="card-header">
                  <h3>{password.name}</h3>
                  <span className={`status-badge ${password.isVerified ? "verified" : "encrypted"}`}>
                    {password.isVerified ? "✅ Verified" : "🔒 Encrypted"}
                  </span>
                </div>
                <div className="card-content">
                  {renderStrengthBar(password.strengthScore)}
                  <div className="risk-indicator">
                    Leak Risk: <span className={`risk-value ${password.leakRisk > 50 ? "high" : "low"}`}>
                      {password.leakRisk}%
                    </span>
                  </div>
                  <div className="card-meta">
                    <span>Created: {new Date(password.timestamp * 1000).toLocaleDateString()}</span>
                    <span>By: {password.creator.substring(0, 6)}...{password.creator.substring(38)}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
          
          {totalPages > 1 && (
            <div className="pagination">
              <button 
                onClick={() => setCurrentPage(Math.max(1, currentPage - 1))}
                disabled={currentPage === 1}
              >
                Previous
              </button>
              <span>Page {currentPage} of {totalPages}</span>
              <button 
                onClick={() => setCurrentPage(Math.min(totalPages, currentPage + 1))}
                disabled={currentPage === totalPages}
              >
                Next
              </button>
            </div>
          )}
        </section>
      </div>
      
      {showCreateModal && (
        <ModalCreatePassword 
          onSubmit={createPasswordCheck} 
          onClose={() => setShowCreateModal(false)} 
          creating={creatingPassword} 
          passwordData={newPasswordData} 
          setPasswordData={setNewPasswordData}
          isEncrypting={isEncrypting}
          calculateStrength={calculatePasswordStrength}
        />
      )}
      
      {selectedPassword && (
        <PasswordDetailModal 
          password={selectedPassword} 
          onClose={() => { 
            setSelectedPassword(null); 
            setDecryptedData(null); 
          }} 
          decryptedData={decryptedData} 
          isDecrypting={isDecrypting || fheIsDecrypting} 
          decryptData={() => decryptData(selectedPassword.encryptedValue)}
          renderStrengthBar={renderStrengthBar}
        />
      )}
      
      {transactionStatus.visible && (
        <div className="transaction-modal">
          <div className="transaction-content">
            <div className={`transaction-icon ${transactionStatus.status}`}>
              {transactionStatus.status === "pending" && <div className="fhe-spinner"></div>}
              {transactionStatus.status === "success" && <div className="success-icon">✓</div>}
              {transactionStatus.status === "error" && <div className="error-icon">✗</div>}
            </div>
            <div className="transaction-message">{transactionStatus.message}</div>
          </div>
        </div>
      )}
    </div>
  );
};

const ModalCreatePassword: React.FC<{
  onSubmit: () => void; 
  onClose: () => void; 
  creating: boolean;
  passwordData: any;
  setPasswordData: (data: any) => void;
  isEncrypting: boolean;
  calculateStrength: (password: string) => { strength: number; risk: number };
}> = ({ onSubmit, onClose, creating, passwordData, setPasswordData, isEncrypting, calculateStrength }) => {
  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setPasswordData({ ...passwordData, [name]: value });
  };

  const { strength, risk } = calculateStrength(passwordData.password);

  return (
    <div className="modal-overlay">
      <div className="create-password-modal">
        <div className="modal-header">
          <h2>Check Password Strength</h2>
          <button onClick={onClose} className="close-modal">&times;</button>
        </div>
        
        <div className="modal-body">
          <div className="fhe-notice">
            <strong>FHE 🔐 Protection</strong>
            <p>Only password length is encrypted and stored. Your password never leaves your device.</p>
          </div>
          
          <div className="form-group">
            <label>Password Name *</label>
            <input 
              type="text" 
              name="name" 
              value={passwordData.name} 
              onChange={handleChange} 
              placeholder="e.g., Gmail password..." 
            />
          </div>
          
          <div className="form-group">
            <label>Password to Check *</label>
            <input 
              type="password" 
              name="password" 
              value={passwordData.password} 
              onChange={handleChange} 
              placeholder="Enter your password..." 
            />
            <div className="strength-preview">
              <div className="preview-label">Estimated Strength: {strength}/100</div>
              <div className="preview-bar">
                <div 
                  className="preview-fill" 
                  style={{ width: `${strength}%` }}
                ></div>
              </div>
              <div className="risk-preview">Leak Risk: {risk}%</div>
            </div>
            <div className="data-type-label">Length will be FHE encrypted</div>
          </div>
        </div>
        
        <div className="modal-footer">
          <button onClick={onClose} className="cancel-btn">Cancel</button>
          <button 
            onClick={onSubmit} 
            disabled={creating || isEncrypting || !passwordData.name || !passwordData.password} 
            className="submit-btn"
          >
            {creating || isEncrypting ? "Encrypting and Checking..." : "Check Strength"}
          </button>
        </div>
      </div>
    </div>
  );
};

const PasswordDetailModal: React.FC<{
  password: PasswordData;
  onClose: () => void;
  decryptedData: number | null;
  isDecrypting: boolean;
  decryptData: () => Promise<number | null>;
  renderStrengthBar: (strength: number) => JSX.Element;
}> = ({ password, onClose, decryptedData, isDecrypting, decryptData, renderStrengthBar }) => {
  const handleDecrypt = async () => {
    if (decryptedData !== null) return;
    await decryptData();
  };

  return (
    <div className="modal-overlay">
      <div className="password-detail-modal">
        <div className="modal-header">
          <h2>Password Analysis Details</h2>
          <button onClick={onClose} className="close-modal">&times;</button>
        </div>
        
        <div className="modal-body">
          <div className="password-info">
            <div className="info-item">
              <span>Password Name:</span>
              <strong>{password.name}</strong>
            </div>
            <div className="info-item">
              <span>Creator:</span>
              <strong>{password.creator.substring(0, 6)}...{password.creator.substring(38)}</strong>
            </div>
            <div className="info-item">
              <span>Date Checked:</span>
              <strong>{new Date(password.timestamp * 1000).toLocaleDateString()}</strong>
            </div>
          </div>
          
          <div className="analysis-section">
            <h3>Strength Analysis</h3>
            {renderStrengthBar(password.strengthScore)}
            
            <div className="risk-assessment">
              <div className="risk-meter">
                <div className="risk-label">Leak Risk Assessment</div>
                <div className={`risk-value-large ${password.leakRisk > 50 ? "high-risk" : "low-risk"}`}>
                  {password.leakRisk}%
                </div>
              </div>
            </div>
          </div>
          
          <div className="fhe-section">
            <h3>FHE Encryption Details</h3>
            
            <div className="fhe-data">
              <div className="data-row">
                <div className="data-label">Password Length:</div>
                <div className="data-value">
                  {password.isVerified && password.decryptedValue ? 
                    `${password.decryptedValue} characters (On-chain Verified)` : 
                    decryptedData !== null ? 
                    `${decryptedData} characters (Locally Decrypted)` : 
                    "🔒 FHE Encrypted"
                  }
                </div>
                <button 
                  className={`decrypt-btn ${(password.isVerified || decryptedData !== null) ? 'decrypted' : ''}`}
                  onClick={handleDecrypt} 
                  disabled={isDecrypting}
                >
                  {isDecrypting ? (
                    "🔓 Verifying..."
                  ) : password.isVerified ? (
                    "✅ Verified"
                  ) : decryptedData !== null ? (
                    "🔄 Re-verify"
                  ) : (
                    "🔓 Verify Length"
                  )}
                </button>
              </div>
            </div>
            
            <div className="fhe-explanation">
              <div className="fhe-icon">🔐</div>
              <div>
                <strong>How FHE Protects Your Password</strong>
                <p>Only the password length is encrypted and stored on-chain. The actual password characters are never transmitted or stored. Strength analysis happens locally using encrypted length data.</p>
              </div>
            </div>
          </div>
        </div>
        
        <div className="modal-footer">
          <button onClick={onClose} className="close-btn">Close</button>
          {!password.isVerified && (
            <button 
              onClick={handleDecrypt} 
              disabled={isDecrypting}
              className="verify-btn"
            >
              {isDecrypting ? "Verifying on-chain..." : "Verify on-chain"}
            </button>
          )}
        </div>
      </div>
    </div>
  );
};

export default App;

