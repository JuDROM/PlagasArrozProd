package backendAPI.service;


import backendAPI.Entity.AuditLog;
import backendAPI.repository.AuditLogRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class LogsService {
    @Autowired
    final AuditLogRepository  logRepository;

    public LogsService(AuditLogRepository logRepository) {
        this.logRepository = logRepository;
    }

    public List<AuditLog> getAllLogs(){
        return logRepository.findAllByOrderByFechaDesc();
    }
    public List<AuditLog> getFirstFiveLogs(){
        return logRepository.findTop5ByOrderByFechaDesc();
    }

}
