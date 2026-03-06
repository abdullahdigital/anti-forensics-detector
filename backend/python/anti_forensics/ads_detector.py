
import os
import sys
import json
import math
import hashlib
import logging
import subprocess
import platform
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Constants
MAX_ADS_SIZE_MB = 10  # Safety limit for ADS reading (10MB)

class ADSStreamType(Enum):
    """Enum for different types of ADS streams"""
    DEFAULT = "$DATA"
    HIDDEN = "hidden"
    METADATA = "metadata"
    ENCRYPTED = "encrypted"
    EXECUTABLE = "executable"
    COMPRESSED = "compressed"
    ZONE_IDENTIFIER = "zone_identifier"
    UNKNOWN = "unknown"

@dataclass
class ADSStream:
    """Data class for ADS stream information"""
    name: str
    full_path: str
    size_bytes: int
    stream_type: ADSStreamType
    creation_time: Optional[datetime] = None
    modification_time: Optional[datetime] = None
    hash_md5: Optional[str] = None
    hash_sha256: Optional[str] = None
    entropy: Optional[float] = None
    is_executable: bool = False
    is_encrypted: bool = False
    risk_score: int = 0
    content_preview: Optional[str] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        result = asdict(self)
        result['stream_type'] = self.stream_type.value
        if self.creation_time:
            result['creation_time'] = self.creation_time.isoformat()
        if self.modification_time:
            result['modification_time'] = self.modification_time.isoformat()
        return result

class ADSDetector:
    """
    Comprehensive ADS detector for Windows NTFS
    Uses PowerShell as primary method (most reliable)
    """
    
    def __init__(self, use_win32api: bool = False, max_scan_depth: int = 2):
        """
        Initialize ADS detector
        
        Args:
            use_win32api: Use pywin32 for detection (optional)
            max_scan_depth: Maximum directory depth for scanning
        """
        self.max_scan_depth = max_scan_depth
        self.use_win32api = use_win32api
        self.win32api_available = False
        
        # Check system platform
        self.system = platform.system()
        self.is_windows = self.system == "Windows"
        self.is_linux = self.system == "Linux"
        
        # Initialize Win32 API if requested and available
        if self.is_windows and self.use_win32api:
            self._init_win32api()
    
        pass # Win32 API removed for Linux compatibility
    
    def detect_ads_comprehensive(self, file_path: str, selected_detectors: List[str] = None) -> Dict[str, Any]:
        """
        Comprehensive ADS detection with multiple fallback methods
        
        Args:
            file_path: Path to file or directory to scan
            selected_detectors: List of detectors to use
            
        Returns:
            Dictionary with detailed ADS analysis
        """
        if not (self.is_windows or self.is_linux):
            return self._non_windows_response(file_path)
        
        if not os.path.exists(file_path):
            return {
                "error": "File or directory not found",
                "file_path": file_path,
                "success": False
            }
        
        try:
            # Normalize path
            file_path = os.path.abspath(file_path)
            
            # Check if it's a directory
            if os.path.isdir(file_path):
                return self.scan_directory_for_ads(file_path, selected_detectors)
            
            # Single file analysis
            return self._analyze_single_file(file_path, selected_detectors)
            
        except PermissionError as e:
            error_msg = f"Permission denied accessing {file_path}"
            logger.error(error_msg)
            return {
                "error": error_msg,
                "file_path": file_path,
                "success": False
            }
        except Exception as e:
            error_msg = f"Error analyzing {file_path}: {str(e)}"
            logger.error(error_msg)
            return {
                "error": error_msg,
                "file_path": file_path,
                "success": False
            }
    
    def _analyze_single_file(self, file_path: str, selected_detectors: List[str] = None) -> Dict[str, Any]:
        """Analyze single file for ADS using multiple detection methods"""
        logger.info(f"Analyzing file for ADS: {file_path}")
        
        # Default to all detectors if none specified
        if selected_detectors is None:
            if self.is_windows:
                selected_detectors = ["powershell", "win32api", "pattern"]
            else:
                selected_detectors = ["xattr", "pattern"]
        
        results = {
            "file_path": file_path,
            "file_size": self._get_file_size(file_path),
            "timestamp": datetime.now().isoformat(),
            "analysis_methods": [],
            "platform": platform.system(),
            "success": True
        }
        
        detected_streams = []
        detection_methods = []
        
        # Method 1: PowerShell (Most reliable)
        if "pattern" in selected_detectors:
            logger.debug("Using pattern-based detection...")
            pattern_streams = self._detect_with_patterns(file_path)
            if pattern_streams:
                for stream in pattern_streams:
                    if not self._stream_exists(stream, detected_streams):
                        detected_streams.append(stream)
                detection_methods.append("pattern")
                results["analysis_methods"].append({
                    "method": "pattern",
                    "streams_found": len(pattern_streams)
                })

        # Method 4: Linux xattr (Linux specific)
        if "xattr" in selected_detectors and self.is_linux:
            logger.debug("Using Linux xattr detection method...")
            xattr_streams = self._detect_with_xattr(file_path)
            if xattr_streams:
                for stream in xattr_streams:
                    if not self._stream_exists(stream, detected_streams):
                        detected_streams.append(stream)
                detection_methods.append("xattr")
                results["analysis_methods"].append({
                    "method": "xattr",
                    "streams_found": len(xattr_streams)
                })
        
        # Analyze detected streams
        if detected_streams:
            logger.info(f"Found {len(detected_streams)} ADS stream(s)")
            
            # Analyze each stream
            analyzed_streams = []
            for stream in detected_streams:
                analyzed_stream = self._analyze_stream(stream)
                analyzed_streams.append(analyzed_stream)
            
            # Sort by risk score (highest first)
            analyzed_streams.sort(key=lambda x: x.risk_score, reverse=True)
            
            results.update({
                "ads_found": True,
                "ads_detected": True, # For ReportGenerator compatibility
                "total_streams": len(analyzed_streams),
                "total_ads_size_bytes": sum(s.size_bytes for s in analyzed_streams),
                "total_ads_size_human": self._format_size(sum(s.size_bytes for s in analyzed_streams)),
                "streams": [s.to_dict() for s in analyzed_streams],
                "ads_streams": [s.to_dict() for s in analyzed_streams], # For ReportGenerator compatibility
                "risk_assessment": self._assess_risk(analyzed_streams),
                "recommendations": self._generate_recommendations(analyzed_streams),
                "summary": f"Found {len(analyzed_streams)} ADS stream(s) totaling {self._format_size(sum(s.size_bytes for s in analyzed_streams))}",
                "detection_methods_used": detection_methods
            })
        else:
            logger.info("No ADS streams found")
            results.update({
                "ads_found": False,
                "ads_detected": False, # For ReportGenerator compatibility
                "total_streams": 0,
                "total_ads_size_bytes": 0,
                "total_ads_size_human": "0 B",
                "streams": [],
                "ads_streams": [], # For ReportGenerator compatibility
                "risk_assessment": {
                    "risk_level": "low",
                    "score": 0,
                    "description": "No ADS detected"
                },
                "recommendations": ["No action required - no ADS detected"],
                "summary": "No ADS streams detected",
                "detection_methods_used": detection_methods
            })
        
        return results
    
    def _detect_with_powershell(self, file_path: str) -> List[ADSStream]:
        """Method removed for Linux compatibility."""
        return []
    
    def _detect_with_win32api(self, file_path: str) -> List[ADSStream]:
        """Method removed for Linux compatibility."""
        return []
    
    def _detect_with_patterns(self, file_path: str) -> List[ADSStream]:
        """Detect ADS by checking common patterns"""
        streams = []
        
        if not self.is_windows:
            return streams
        
        # Common ADS patterns to check
        test_patterns = [
            "Zone.Identifier",
            "Zone.Identifier:$DATA",
            "hidden.txt",
            "secret.txt",
            "password.txt",
            "data.txt",
            "info.txt",
            "metadata.txt"
        ]
        
        for pattern in test_patterns:
            test_path = f"{file_path}:{pattern}"
            if os.path.exists(test_path):
                try:
                    size = os.path.getsize(test_path)
                except:
                    size = 0
                
                stream = ADSStream(
                    name=pattern,
                    full_path=test_path,
                    size_bytes=size,
                    stream_type=self._classify_stream(pattern)
                )
                streams.append(stream)
        
        return streams

    def _detect_with_xattr(self, file_path: str) -> List[ADSStream]:
        """Detect ADS using Linux Extended Attributes (xattr)"""
        streams = []
        
        if not self.is_linux:
            return streams
            
        try:
            # Use getfattr to list all attributes
            # -d: dump all attributes
            # -m -: match all attributes (including user., trusted., security.)
            # --absolute-names: don't strip leading /
            cmd = ['getfattr', '-d', '-m', '-', '--absolute-names', file_path]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                timeout=5
            )
            
            if result.returncode == 0 and result.stdout.strip():
                # Output format is typically:
                # # file: /path/to/file
                # user.attribute="value"
                # user.params=0s... (base64 or hex)
                
                # We need to parse this properly. 
                # Note: getfattr output can be complex if values are binary.
                
                current_file_match = False
                lines = result.stdout.strip().split('\n')
                
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                        
                    if line.startswith("# file:"):
                        # Verify we're looking at the right file (though we only queried one)
                        continue
                        
                    if '=' in line:
                        # Parse attribute=value
                        name_part, value_part = line.split('=', 1)
                        name = name_part.strip()
                        
                        # Handle values
                        # If value is quoted, strip quotes. e.g. "value"
                        if value_part.startswith('"') and value_part.endswith('"'):
                            value_part = value_part[1:-1]
                        
                        # Calculate size (approximation as we only have the string representation)
                        # To get exact size, we might need --only-values for each attr, but that's expensive
                        size = len(value_part) 
                        if value_part.startswith('0s'): # Hex/Base64 encoding indicator in getfattr
                             # Simple approximation for now
                             size = len(value_part)
                        
                        stream = ADSStream(
                            name=name,
                            full_path=f"{file_path}:{name}", # Virtual path representation
                            size_bytes=size,
                            stream_type=self._classify_stream(name),
                            content_preview=value_part[:100] if len(value_part) > 100 else value_part
                        )
                        streams.append(stream)
                        
        except FileNotFoundError:
             logger.warning("getfattr command not found. Please install 'attr' package.")
             # Return a special pseudo-stream so the user sees the error
             error_stream = ADSStream(
                 name="MISSING_DEPENDENCY",
                 full_path="System Detection",
                 size_bytes=0,
                 stream_type=ADSStreamType.UNKNOWN,
                 content_preview="Error: 'getfattr' command not found. Please install 'attr' package on the server.",
                 risk_score=100  # High risk because functionality is broken
             )
             streams.append(error_stream)
        except Exception as e:
            logger.debug(f"xattr detection failed: {str(e)}")
            
        return streams
    
    def _analyze_stream(self, stream: ADSStream) -> ADSStream:
        """Perform deep analysis on a single stream"""
        try:
            # Get file times if possible
            try:
                stat_info = os.stat(stream.full_path)
                stream.creation_time = datetime.fromtimestamp(stat_info.st_ctime)
                stream.modification_time = datetime.fromtimestamp(stat_info.st_mtime)
            except:
                pass
            
            # Read and analyze stream content (for small streams)
            # Note: For Linux xattr, we might have already populated content_preview, but we can't "open" the stream path like in Windows.
            if self.is_windows and 0 < stream.size_bytes <= (MAX_ADS_SIZE_MB * 1024 * 1024):
                try:
                    with open(stream.full_path, 'rb') as f:
                        content = f.read(min(stream.size_bytes, 65536))  # Read up to 64KB
                    
                    # Calculate hashes
                    stream.hash_md5 = hashlib.md5(content).hexdigest()
                    stream.hash_sha256 = hashlib.sha256(content).hexdigest()
                    
                    # Calculate entropy
                    stream.entropy = self._calculate_entropy(content)
                    
                    # Check if executable
                    stream.is_executable = self._is_executable(content)
                    
                    # Check if encrypted
                    stream.is_encrypted = self._is_encrypted(content, stream.entropy)
                    
                    # Create content preview
                    try:
                        # Try to decode as text
                        text_content = content.decode('utf-8', errors='ignore').strip()
                        if text_content:
                            if len(text_content) > 100:
                                stream.content_preview = text_content[:100] + "..."
                            else:
                                stream.content_preview = text_content
                        else:
                            stream.content_preview = f"Binary data ({len(content)} bytes)"
                    except:
                        stream.content_preview = f"Binary data ({len(content)} bytes)"
                    
                except (PermissionError, IOError, OSError) as e:
                    logger.debug(f"Cannot read stream {stream.name}: {str(e)}")
                    stream.content_preview = "Access denied"
            
            # Update risk score
            stream.risk_score = self._calculate_stream_risk(stream)
            
        except Exception as e:
            logger.debug(f"Error analyzing stream {stream.name}: {str(e)}")
        
        return stream
    
    def scan_directory_for_ads(self, directory_path: str, selected_detectors: List[str] = None) -> Dict[str, Any]:
        """Recursively scan directory for files with ADS"""
        if not (self.is_windows or self.is_linux):
            return self._non_windows_response(directory_path)
        
        logger.info(f"Scanning directory for ADS: {directory_path}")
        
        ads_files = []
        total_files_scanned = 0
        total_ads_found = 0
        
        try:
            for root, dirs, files in os.walk(directory_path):
                # Check depth
                depth = root[len(directory_path):].count(os.sep)
                if depth > self.max_scan_depth:
                    continue
                
                for file in files:
                    total_files_scanned += 1
                    file_path = os.path.join(root, file)
                    
                    try:
                        result = self._analyze_single_file(file_path, selected_detectors)
                        if result.get("ads_found", False):
                            ads_files.append(result)
                            total_ads_found += result.get("total_streams", 0)
                            
                            # Limit for performance
                            if len(ads_files) >= 20:
                                logger.warning("Reached limit of 20 files with ADS in directory scan")
                                break
                    except Exception as e:
                        logger.debug(f"Error scanning {file_path}: {str(e)}")
                        continue
                
                if len(ads_files) >= 20:
                    break
            
            return {
                "directory_path": directory_path,
                "scan_summary": {
                    "total_files_scanned": total_files_scanned,
                    "files_with_ads": len(ads_files),
                    "total_ads_streams": total_ads_found,
                    "scan_timestamp": datetime.now().isoformat(),
                    "max_depth_scanned": self.max_scan_depth
                },
                "ads_files": ads_files,
                "recommendations": self._generate_directory_recommendations(len(ads_files), total_files_scanned, total_ads_found),
                "success": True
            }
            
        except Exception as e:
            logger.error(f"Directory scan failed: {str(e)}")
            return {
                "error": f"Directory scan failed: {str(e)}",
                "directory_path": directory_path,
                "success": False
            }
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data or len(data) == 0:
            return 0.0
        
        entropy = 0.0
        size = len(data)
        
        # Count frequency of each byte value (0-255)
        frequency = [0] * 256
        for byte in data:
            frequency[byte] += 1
        
        # Calculate entropy
        for count in frequency:
            if count > 0:
                probability = count / size
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _is_executable(self, data: bytes) -> bool:
        """Check if data appears to be executable"""
        if len(data) < 2:
            return False
        
        # Check for MZ header (Windows PE)
        if data[:2] == b'MZ':
            return True
        
        # Check for ELF header (Linux)
        if len(data) >= 4 and data[:4] == b'\x7fELF':
            return True
        
        # Check for shebang
        if data[:2] == b'#!':
            return True
        
        return False
    
    def _is_encrypted(self, data: bytes, entropy: float) -> bool:
        """Check if data appears to be encrypted"""
        if len(data) < 16:
            return False
        
        # High entropy indicates encrypted/compressed data
        if entropy > 7.0:
            return True
        
        # Check for known encryption patterns
        encrypted_patterns = [
            b'Salted__',
            b'-----BEGIN',
            b'U2FsdGVkX1'  # OpenSSL "Salted__" in base64
        ]
        
        return any(data.startswith(pattern) for pattern in encrypted_patterns)
    
    def _classify_stream(self, stream_name: str) -> ADSStreamType:
        """Classify stream type based on name"""
        stream_name_lower = stream_name.lower()
        
        if 'zone.identifier' in stream_name_lower:
            return ADSStreamType.ZONE_IDENTIFIER
        elif any(ext in stream_name_lower for ext in ['.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs']):
            return ADSStreamType.EXECUTABLE
        elif any(word in stream_name_lower for word in ['secret', 'hidden', 'password', 'private']):
            return ADSStreamType.HIDDEN
        elif 'encrypt' in stream_name_lower:
            return ADSStreamType.ENCRYPTED
        elif any(ext in stream_name_lower for ext in ['.zip', '.rar', '.7z']):
            return ADSStreamType.COMPRESSED
        elif any(word in stream_name_lower for word in ['metadata', 'summary', 'info']):
            return ADSStreamType.METADATA
        elif stream_name_lower.startswith('user.') or stream_name_lower.startswith('trusted.') or stream_name_lower.startswith('security.') or stream_name_lower.startswith('system.'):
             # Handle Linux xattr namespaces if none of the above matched
             if 'zone.identifier' in stream_name_lower: # Handle user.Zone.Identifier
                 return ADSStreamType.ZONE_IDENTIFIER
             return ADSStreamType.METADATA
        else:
            return ADSStreamType.UNKNOWN
    
    def _calculate_stream_risk(self, stream: ADSStream) -> int:
        """Calculate risk score for a stream (0-100)"""
        risk_score = 0
        
        # Size-based risk
        if stream.size_bytes > 10 * 1024 * 1024:  # > 10MB
            risk_score += 40
        elif stream.size_bytes > 1 * 1024 * 1024:  # > 1MB
            risk_score += 25
        elif stream.size_bytes > 100 * 1024:  # > 100KB
            risk_score += 15
        
        # Type-based risk
        if stream.stream_type == ADSStreamType.EXECUTABLE:
            risk_score += 50
        elif stream.stream_type == ADSStreamType.HIDDEN:
            risk_score += 40
        elif stream.stream_type == ADSStreamType.ENCRYPTED:
            risk_score += 35
        elif stream.stream_type == ADSStreamType.ZONE_IDENTIFIER:
            risk_score += 5  # Common and usually safe
        
        # Content-based risk
        if stream.is_executable:
            risk_score += 40
        if stream.is_encrypted:
            risk_score += 30
        
        # Name suspiciousness
        suspicious_keywords = ['malware', 'trojan', 'backdoor', 'virus', 'keylogger']
        for keyword in suspicious_keywords:
            if keyword in stream.name.lower():
                risk_score += 60
                break
        
        return min(risk_score, 100)
    
    def _assess_risk(self, streams: List[ADSStream]) -> Dict[str, Any]:
        """Assess overall risk based on detected streams"""
        if not streams:
            return {
                "risk_level": "low",
                "score": 0,
                "description": "No ADS detected",
                "details": {}
            }
        
        total_risk = sum(s.risk_score for s in streams)
        avg_risk = total_risk / len(streams)
        
        # Count by category
        critical = [s for s in streams if s.risk_score >= 80]
        high = [s for s in streams if 60 <= s.risk_score < 80]
        medium = [s for s in streams if 30 <= s.risk_score < 60]
        low = [s for s in streams if s.risk_score < 30]
        
        executable_count = len([s for s in streams if s.is_executable])
        encrypted_count = len([s for s in streams if s.is_encrypted])
        
        # Determine overall risk
        if critical or avg_risk >= 70:
            risk_level = "critical"
        elif high or avg_risk >= 50:
            risk_level = "high"
        elif medium or avg_risk >= 30:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        return {
            "risk_level": risk_level,
            "score": int(avg_risk),
            "description": self._get_risk_description(risk_level, len(critical), executable_count),
            "details": {
                "total_streams": len(streams),
                "critical_streams": len(critical),
                "high_risk_streams": len(high),
                "medium_risk_streams": len(medium),
                "low_risk_streams": len(low),
                "executable_streams": executable_count,
                "encrypted_streams": encrypted_count,
                "total_size_bytes": sum(s.size_bytes for s in streams),
                "total_size_human": self._format_size(sum(s.size_bytes for s in streams))
            }
        }
    
    def _get_risk_description(self, risk_level: str, critical_count: int, executable_count: int) -> str:
        """Generate risk description"""
        descriptions = {
            "critical": f"CRITICAL: {critical_count} critical ADS found including {executable_count} executables",
            "high": f"HIGH: Suspicious ADS detected with {executable_count} executables",
            "medium": "MEDIUM: Potentially suspicious ADS detected",
            "low": "LOW: Normal or non-suspicious ADS"
        }
        return descriptions.get(risk_level, "Unknown risk level")
    
    def _generate_recommendations(self, streams: List[ADSStream]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if not streams:
            recommendations.append("No action required")
            return recommendations
        
        # Check for high-risk indicators
        has_executable = any(s.is_executable for s in streams)
        has_encrypted = any(s.is_encrypted for s in streams)
        has_critical = any(s.risk_score >= 80 for s in streams)
        
        if has_critical:
            recommendations.append("IMMEDIATE ACTION: Critical risk ADS detected")
            recommendations.append("Isolate and investigate the file immediately")
            recommendations.append("Scan with antivirus software")
        
        if has_executable:
            recommendations.append("WARNING: Executable content in ADS")
            recommendations.append("Do not execute any ADS content")
            recommendations.append("Check file reputation on VirusTotal")
        
        if has_encrypted:
            recommendations.append("NOTE: Encrypted content detected")
            recommendations.append("Investigate why encryption is used")
        
        # General recommendations
        recommendations.append("Review all ADS streams for legitimacy")
        recommendations.append("Consider removing unnecessary ADS")
        recommendations.append("Monitor file for changes")
        
        return recommendations
    
    def _generate_directory_recommendations(self, ads_files_count: int, total_files: int, total_ads: int) -> List[str]:
        """Generate recommendations for directory scan"""
        recommendations = []
        
        if ads_files_count == 0:
            recommendations.append("Directory clean - no ADS detected")
            return recommendations
        
        percentage = (ads_files_count / max(total_files, 1)) * 100
        
        recommendations.append(f"Found {ads_files_count} files with ADS ({percentage:.1f}% of files)")
        recommendations.append(f"Total ADS streams: {total_ads}")
        
        if percentage > 20:
            recommendations.append("CRITICAL: High ADS prevalence - investigate immediately")
        elif percentage > 10:
            recommendations.append("HIGH: Significant ADS presence - review needed")
        elif percentage > 5:
            recommendations.append("MEDIUM: Elevated ADS presence")
        else:
            recommendations.append("LOW: Normal ADS level")
        
        return recommendations
    
    def _get_file_size(self, file_path: str) -> int:
        """Get file size safely"""
        try:
            return os.path.getsize(file_path)
        except:
            return 0
    
    def _format_size(self, size_bytes: int) -> str:
        """Format size in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} TB"
    
    def _stream_exists(self, stream: ADSStream, stream_list: List[ADSStream]) -> bool:
        """Check if stream already exists in list"""
        return any(s.name == stream.name for s in stream_list)
    
    def _non_windows_response(self, file_path: str) -> Dict[str, Any]:
        """Generate response for non-Windows systems"""
        return {
            "file_path": file_path,
            "ads_found": False,
            "ads_found": False,
            "note": "Alternate Data Streams are Windows NTFS-specific and Linux xattr-specific",
            "platform": platform.system(),
            "timestamp": datetime.now().isoformat(),
            "success": True
        }

# Helper functions for the Flask API
def create_test_ads_file(file_path: str = "test_ads_demo.txt") -> Tuple[bool, str]:
    """
    Create a test file with ADS for demonstration
    Returns: (success, message)
    """
    if platform.system() == "Windows":
        try:
            # Create main file
            with open(file_path, 'w') as f:
                f.write("Main content for testing ADS detection\n")
            
            # Create ADS using PowerShell
            ps_commands = [
                f'Set-Content -Path "{file_path}" -Value "Hidden Zone Info" -Stream "Zone.Identifier"',
                f'Set-Content -Path "{file_path}" -Value "Secret hidden data" -Stream "hidden.txt"'
            ]
            
            for cmd in ps_commands:
                result = subprocess.run(
                    ['powershell', '-Command', cmd],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                if result.returncode != 0:
                    logger.warning(f"Failed to create ADS: {result.stderr}")
            
            return True, f"Test file created: {file_path} with ADS streams"
            
        except Exception as e:
            return False, f"Failed to create test file: {str(e)}"

    elif platform.system() == "Linux":
        try:
            # Create main file
            with open(file_path, 'w') as f:
                f.write("Main content for testing ADS detection (Linux xattr)\n")
                
            # Create ADS using setfattr
            # We use user. namespace for user attributes
            commands = [
                ['setfattr', '-n', 'user.Zone.Identifier', '-v', 'Hidden Zone Info', file_path],
                ['setfattr', '-n', 'user.hidden.txt', '-v', 'Secret hidden data', file_path]
            ]
            
            for cmd in commands:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode != 0:
                     # Attempt to install it? No, just warn.
                     # Often setfattr requires the filesystem to be mounted with user_xattr, but mostly it works on modern ext4
                     logger.warning(f"Failed to create xattr: {result.stderr}. Make sure attr is installed and filesystem supports xattrs.")
                     return False, f"Failed to create xattr (is 'attr' installed?): {result.stderr}"

            return True, f"Test file created: {file_path} with xattrs (ADS equivalent)"

        except Exception as e:
            return False, f"Failed to create test file: {str(e)}"
    
    else:
        return False, "Test only works on Windows and Linux"

def detect_ads(file_path: str) -> Dict[str, Any]:
    """
    Wrapper function for backward compatibility with analyzer.py
    """
    detector = ADSDetector()
    return detector.detect_ads_comprehensive(file_path)

# For direct testing
if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description="ADS Detector")
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("--test", action="store_true", help="Create test file first")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Create test file if requested
    if args.test:
        success, message = create_test_ads_file(args.path)
        print(message)
        if not success:
            sys.exit(1)
    
    # Run detection
    detector = ADSDetector()
    result = detector.detect_ads_comprehensive(args.path)
    
    # Print results
    print(json.dumps(result, indent=2, default=str, ensure_ascii=False))