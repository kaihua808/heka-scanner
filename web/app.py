from flask import Flask, render_template, request, jsonify, Response
import threading
import json
import time
from datetime import datetime
from typing import Dict, Any, List

# 全局变量用于跟踪扫描进度
scan_progress_data = {}
progress_lock = threading.Lock()

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from web.scan_service import ScanService
from web.services.db_service import db_service

app = Flask(__name__,
            template_folder='../templates',
            static_folder='../static')

scan_service = ScanService()

# 使用更持久的存储方式
if not hasattr(app, 'scan_history'):
    app.scan_history = []
if not hasattr(app, 'scan_cache'):
    app.scan_cache = {}
if not hasattr(app, 'history_lock'):
    app.history_lock = threading.Lock()

scan_history = app.scan_history
scan_cache = app.scan_cache
history_lock = app.history_lock


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.get_json()

    ip_or_cidr = data.get('ip', '')
    port_str = data.get('ports', '1-1000')
    scan_mode = data.get('mode', 'full')

    if not ip_or_cidr:
        return jsonify({'error': 'IP地址不能为空'}), 400

    scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}"
    
    # 同步执行扫描（不使用异步，确保稳定）
    try:
        # 添加进度回调
        def progress_callback(completed, total):
            pass
            
        result = scan_service.scan(
            ip_or_cidr=ip_or_cidr,
            port_str=port_str,
            scan_mode=scan_mode,
            progress_callback=progress_callback
        )

        # 缓存结果
        scan_cache[scan_id] = result
        
        # 添加到历史（内存 + MySQL）
        with history_lock:
            scan_history.append({
                'id': scan_id,
                'timestamp': datetime.now().isoformat(),
                'target': ip_or_cidr,
                'ports': port_str,
                'mode': scan_mode,
                'status': 'completed' if result.get('success') else 'failed',
                'open_ports': result.get('stats', {}).get('open', 0),
                'duration': result.get('duration', 0)
            })
        
        # 保存到MySQL
        if db_service.mysql_available:
            db_record_id = db_service.save_scan_record(ip_or_cidr, port_str, scan_mode)
            if db_record_id:
                db_service.update_scan_status(
                    db_record_id,
                    'completed' if result.get('success') else 'failed',
                    result.get('results', []),
                    result.get('stats', {}),
                    result.get('duration', 0)
                )
                db_service.save_scan_results(db_record_id, result.get('results', []))

        return jsonify({
            'status': 'completed' if result.get('success') else 'failed',
            'scan_id': scan_id,
            'message': '扫描完成' if result.get('success') else result.get('error', '扫描失败'),
            'results': result.get('results', []),
            'stats': result.get('stats', {}),
            'violation': result.get('violation')
        })

    except Exception as e:
        print(f"Scan error: {e}")
        with history_lock:
            scan_history.append({
                'id': scan_id,
                'timestamp': datetime.now().isoformat(),
                'target': ip_or_cidr,
                'ports': port_str,
                'mode': scan_mode,
                'status': 'failed',
                'open_ports': 0,
                'duration': 0
            })
        
        # 保存到MySQL
        if db_service.mysql_available:
            db_record_id = db_service.save_scan_record(ip_or_cidr, port_str, scan_mode)
            if db_record_id:
                db_service.update_scan_status(db_record_id, 'failed')
        
        violation = scan_service.get_last_violation()
        return jsonify({
            'status': 'failed',
            'scan_id': scan_id,
            'message': str(e),
            'results': [],
            'stats': {},
            'violation': violation
        })


@app.route('/api/results')
def get_results():
    with history_lock:
        if not scan_history:
            return jsonify({'results': [], 'stats': {}, 'violation': None, 'scan_id': None})

        latest_scan = scan_history[-1]
        scan_id = latest_scan['id']
        
        if latest_scan['status'] == 'failed':
            violation = scan_service.get_last_violation()
            return jsonify({
                'results': [], 
                'stats': {}, 
                'violation': violation,
                'sla': {},
                'scan_id': scan_id
            })

        if latest_scan['status'] != 'completed':
            return jsonify({'results': [], 'stats': {}, 'violation': None, 'scan_id': scan_id})

        # 从缓存获取结果
        if scan_id in scan_cache:
            result = scan_cache[scan_id]
            stats = result.get('stats', {})
            # 确保stats包含必要字段
            if not isinstance(stats, dict):
                stats = {}
            return jsonify({
                'results': result.get('results', []),
                'stats': {
                    'open': stats.get('open', 0),
                    'closed': stats.get('closed', 0),
                    'filtered': stats.get('filtered', 0),
                    'total': stats.get('total', 0),
                    'duration': stats.get('duration', 0)
                },
                'sla': result.get('sla', {}),
                'violation': None,
                'scan_id': scan_id
            })

        # 如果缓存中没有，重新扫描并缓存
        result = scan_service.scan(
            ip_or_cidr=latest_scan['target'],
            port_str=latest_scan['ports'],
            scan_mode=latest_scan.get('mode', 'full')
        )
        scan_cache[scan_id] = result
        
        stats = result.get('stats', {})
        if not isinstance(stats, dict):
            stats = {}
            
        return jsonify({
            'results': result.get('results', []),
            'stats': {
                'open': stats.get('open', 0),
                'closed': stats.get('closed', 0),
                'filtered': stats.get('filtered', 0),
                'total': stats.get('total', 0),
                'duration': stats.get('duration', 0)
            },
            'sla': result.get('sla', {}),
            'violation': None,
            'scan_id': scan_id
        })


@app.route('/api/results/<scan_id>')
def get_scan_results(scan_id: str):
    with history_lock:
        scan = next((s for s in scan_history if s['id'] == scan_id), None)
        if not scan:
            # 尝试从MySQL获取
            if db_service.mysql_available:
                db_record = db_service.get_scan_record(scan_id)
                if db_record:
                    return jsonify({
                        'results': db_record.get('results', []),
                        'stats': db_record.get('stats', {}),
                        'sla': {},
                        'violation': None,
                        'scan_id': scan_id
                    })
            return jsonify({'error': 'Scan not found'}), 404

        # 检查扫描是否失败（违规）
        if scan.get('status') == 'failed':
            violation = scan_service.get_last_violation()
            return jsonify({
                'results': [],
                'stats': {},
                'violation': violation,
                'sla': {},
                'scan_id': scan_id
            })

        if scan_id in scan_cache:
            result = scan_cache[scan_id]
            return jsonify({
                'results': result.get('results', []),
                'stats': result.get('stats', {}),
                'sla': result.get('sla', {}),
                'violation': None,
                'scan_id': scan_id
            })

        result = scan_service.scan(
            ip_or_cidr=scan['target'],
            port_str=scan['ports'],
            scan_mode=scan.get('mode', 'full')
        )
        scan_cache[scan_id] = result

        return jsonify({
            'results': result.get('results', []),
            'stats': result.get('stats', {}),
            'sla': result.get('sla', {})
        })


@app.route('/api/history')
def get_history():
    with history_lock:
        history_data = scan_history[-50:]
    
    # 如果MySQL可用，合并数据库中的历史记录
    if db_service.mysql_available:
        db_records = db_service.get_all_records(limit=50)
        if db_records:
            # 合并去重，优先使用内存中的最新数据
            record_ids = set(r['id'] for r in history_data)
            for db_record in db_records:
                if db_record['id'] not in record_ids:
                    history_data.append(db_record)
    
    return jsonify({'history': history_data})


@app.route('/api/stats')
def get_stats():
    with history_lock:
        total_scans = len(scan_history)
        total_open_ports = sum(s.get('open_ports', 0) for s in scan_history)
        completed_scans = [s for s in scan_history if s['status'] == 'completed']

        avg_duration = 0
        if completed_scans:
            avg_duration = sum(s.get('duration', 0) for s in completed_scans) / len(completed_scans)

    return jsonify({
        'total_scans': total_scans,
        'total_open_ports': total_open_ports,
        'sla_pass_rate': 100.0,
        'avg_duration': avg_duration
    })


@app.route('/api/export', methods=['POST'])
def export_results():
    data = request.get_json()
    format_type = data.get('format', 'json')
    scan_id = data.get('scan_id')

    with history_lock:
        if scan_id:
            scan = next((s for s in scan_history if s['id'] == scan_id), None)
            if not scan:
                # 尝试从MySQL获取
                if db_service.mysql_available:
                    db_record = db_service.get_scan_record(scan_id)
                    if db_record:
                        scan = db_record
                    else:
                        return jsonify({'error': 'Scan not found'}), 404
                else:
                    return jsonify({'error': 'Scan not found'}), 404
        elif scan_history:
            scan = scan_history[-1]
            scan_id = scan['id']
        else:
            return jsonify({'error': 'No scan data'}), 400

        if scan_id in scan_cache:
            result = scan_cache[scan_id]
        elif isinstance(scan, dict) and scan.get('results'):
            result = {'results': scan.get('results', []), 'stats': scan.get('stats', {})}
        else:
            result = scan_service.scan(ip_or_cidr=scan['target'], port_str=scan['ports'])
            scan_cache[scan_id] = result
        
        results = result.get('results', [])

    if format_type == 'json':
        content = json.dumps(results, indent=2, ensure_ascii=False)
        return Response(
            content,
            mimetype='application/json',
            headers={'Content-Disposition': 'attachment; filename=scan_results.json'}
        )

    elif format_type == 'csv':
        lines = ['IP,Port,Status,Service,Risk_Level,Response_Time_ms']
        for r in results:
            lines.append(f"{r['ip']},{r['port']},{r['status']},{r.get('service','')},{r.get('risk_level','')},{r.get('response_time','')}")

        content = '\n'.join(lines)
        return Response(
            content,
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=scan_results.csv'}
        )

    return jsonify({'error': 'Unsupported format'}), 400


@app.route('/api/scan/progress')
def scan_progress():
    ip = request.args.get('ip')
    ports = request.args.get('ports')
    scan_mode = request.args.get('mode', 'full')
    request_id = f"{ip}_{ports}_{scan_mode}_{datetime.now().timestamp()}"
    
    def generate():
        # 异步执行扫描
        def do_scan():
            nonlocal request_id
            try:
                def progress_callback(completed, total, open_count=0):
                    with progress_lock:
                        scan_progress_data[request_id] = {
                            'completed': completed,
                            'total': total,
                            'percentage': round((completed / total) * 100) if total > 0 else 0,
                            'open_count': open_count,
                            'status': 'scanning'
                        }
                
                result = scan_service.scan(
                    ip_or_cidr=ip,
                    port_str=ports,
                    scan_mode=scan_mode,
                    progress_callback=progress_callback
                )
                
                scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}"
                scan_cache[scan_id] = result
                
                with history_lock:
                    scan_history.append({
                        'id': scan_id,
                        'timestamp': datetime.now().isoformat(),
                        'target': ip,
                        'ports': ports,
                        'mode': scan_mode,
                        'status': 'completed' if result.get('success') else 'failed',
                        'open_ports': result.get('stats', {}).get('open', 0),
                        'duration': result.get('duration', 0)
                    })
                
                # 保存到MySQL
                if db_service.mysql_available:
                    db_record_id = db_service.save_scan_record(ip, ports, scan_mode)
                    if db_record_id:
                        db_service.update_scan_status(
                            db_record_id,
                            'completed' if result.get('success') else 'failed',
                            result.get('results', []),
                            result.get('stats', {}),
                            result.get('duration', 0)
                        )
                        db_service.save_scan_results(db_record_id, result.get('results', []))
                
                # 更新最终进度
                with progress_lock:
                    scan_progress_data[request_id] = {
                        'completed': 100,
                        'total': 100,
                        'percentage': 100,
                        'open_count': result.get('stats', {}).get('open', 0),
                        'status': 'completed',
                        'scan_id': scan_id,
                        'success': result.get('success', False)
                    }
                    
            except Exception as e:
                with progress_lock:
                    scan_progress_data[request_id] = {
                        'completed': 0,
                        'total': 0,
                        'percentage': 0,
                        'open_count': 0,
                        'status': 'error',
                        'error': str(e)
                    }
        
        scan_thread = threading.Thread(target=do_scan)
        scan_thread.start()
        
        # 增加超时时间，最多等待300秒（5分钟）
        timeout = 300
        elapsed = 0
        
        while elapsed < timeout:
            with progress_lock:
                progress = scan_progress_data.get(request_id)
            
            if progress:
                if progress['status'] == 'completed' or progress['status'] == 'error':
                    # 确保发送多次完成信号，防止前端错过
                    for _ in range(3):
                        yield f"data: {json.dumps(progress)}\n\n"
                        time.sleep(0.1)
                    with progress_lock:
                        if request_id in scan_progress_data:
                            del scan_progress_data[request_id]
                    return
                yield f"data: {json.dumps(progress)}\n\n"
            
            time.sleep(1)
            elapsed += 1
        
        # 超时处理
        with progress_lock:
            scan_progress_data[request_id] = {
                'completed': 0,
                'total': 0,
                'percentage': 0,
                'open_count': 0,
                'status': 'timeout',
                'error': '扫描超时'
            }
            yield f"data: {json.dumps(scan_progress_data[request_id])}\n\n"
            del scan_progress_data[request_id]
    
    response = Response(generate(), mimetype='text/event-stream')
    response.headers['Cache-Control'] = 'no-cache'
    response.headers['Connection'] = 'keep-alive'
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
