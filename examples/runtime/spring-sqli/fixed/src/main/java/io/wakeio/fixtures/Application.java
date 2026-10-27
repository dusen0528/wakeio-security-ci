package io.wakeio.fixtures;

import java.util.List;
import java.util.Map;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.web.bind.annotation.*;
import io.swagger.v3.oas.annotations.media.Schema;

@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}

@RestController
class ItemController {
    private final JdbcTemplate jdbc;
    private static final RowMapper<Item> ITEM = (row, index) ->
        new Item(row.getInt("id"), row.getString("name"));

    ItemController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @GetMapping("/api/items/search")
    public List<Item> searchGet(@RequestParam("name") String name) {
        return search(name);
    }

    @PostMapping(value = "/api/items/search", consumes = "application/json")
    public List<Item> searchPost(@RequestBody SearchRequest body) {
        return search(body.name());
    }

    @GetMapping("/api/items/safe-search")
    public List<Item> safeSearch(@RequestParam("name") String name) {
        return jdbc.query("SELECT id,name FROM items WHERE name = ?", ITEM, name);
    }

    @GetMapping("/api/ping")
    public Map<String, String> ping(@RequestParam(value = "name", defaultValue = "ok") String name) {
        return Map.of("echo", name);
    }

    @GetMapping("/api/untouched")
    public Map<String, String> untouched() {
        return Map.of("status", "not-requested");
    }

    private List<Item> search(String name) {
        String sql = "SELECT id,name FROM items WHERE name = ?";
        return jdbc.query(sql, ITEM, name);
    }

    @ExceptionHandler(DataAccessException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Map<String, String> databaseFailure() {
        return Map.of("error", "query_failed");
    }

    public record Item(int id, String name) {}
    public record SearchRequest(@Schema(requiredMode = Schema.RequiredMode.REQUIRED) String name) {}
}
