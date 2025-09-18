"""
Release Report Generator Integration for Flask App
"""

import sys
import os

# Add the original release report generator to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..'))

try:
    from release_report_generator import ReleaseReportGenerator as OriginalGenerator
    
    class ReleaseReportGenerator(OriginalGenerator):
        """Enhanced release report generator for Flask integration."""
        
        def generate_report_data(self, base_branch, target_branch, target_version):
            """Generate report data without writing to file."""
            self.analyze_stories(base_branch, target_branch, target_version)
            
            # Get all the data components
            ai_summary = self.get_openai_consolidation()
            coverage_info = self.get_sonarqube_coverage(target_branch)
            vulnerabilities = self.get_veracode_vulnerabilities()
            
            # Return structured data
            return {
                'stories': [story.__dict__ for story in self.stories],
                'ai_summary': ai_summary,
                'coverage_info': coverage_info.__dict__,
                'vulnerabilities': [vuln.__dict__ for vuln in vulnerabilities],
                'metadata': {
                    'base_branch': base_branch,
                    'target_branch': target_branch,
                    'target_version': target_version,
                    'total_stories': len(self.stories),
                    'generation_time': datetime.now().isoformat()
                }
            }
            
except ImportError:
    # Fallback implementation if original generator is not available
    class ReleaseReportGenerator:
        def __init__(self, config):
            self.config = config
            self.stories = []
            
        def generate_report_data(self, base_branch, target_branch, target_version):
            # Mock implementation for development
            return {
                'stories': [],
                'ai_summary': 'Mock AI summary - original generator not available',
                'coverage_info': {'current_coverage': 85.0, 'branch': target_branch},
                'vulnerabilities': [],
                'metadata': {
                    'base_branch': base_branch,
                    'target_branch': target_branch,
                    'target_version': target_version,
                    'total_stories': 0,
                    'generation_time': datetime.now().isoformat()
                }
            }
