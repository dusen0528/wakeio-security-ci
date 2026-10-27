package io.wakeio.jdbcfixtures;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.sql.*;
import javax.sql.DataSource;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpStatus;
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
    private final DataSource dataSource;
    ItemController(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @GetMapping("/api/items/search")
    public List<Item> searchGet(@RequestParam("name") String name) throws SQLException {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement("SELECT id,name FROM items WHERE name = ?")) {
            statement.setString(1, name);
            return read(statement.executeQuery());
        }
    }

    @PostMapping(value = "/api/items/search", consumes = "application/json")
    public List<Item> searchPost(@RequestBody SearchRequest body) throws SQLException {
        String name = body.name();
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement("SELECT id,name FROM items WHERE name = ?")) {
            statement.setString(1, name);
            return read(statement.executeQuery());
        }
    }

    @GetMapping("/api/items/safe-search")
    public List<Item> safeSearch(@RequestParam("name") String name) throws SQLException {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement("SELECT id,name FROM items WHERE name = ?")) {
            statement.setString(1, name);
            return read(statement.executeQuery());
        }
    }

    @GetMapping("/api/ping")
    public Map<String, String> ping(@RequestParam(value = "name", defaultValue = "ok") String name) {
        return Map.of("echo", name);
    }

    @GetMapping("/api/untouched")
    public Map<String, String> untouched() {
        return Map.of("status", "not-requested");
    }

    private List<Item> read(ResultSet rows) throws SQLException {
        try (rows) {
            List<Item> items = new ArrayList<>();
            while (rows.next()) {
                items.add(new Item(rows.getInt("id"), rows.getString("name")));
            }
            return items;
        }
    }

    @ExceptionHandler(SQLException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Map<String, String> databaseFailure() {
        return Map.of("error", "query_failed");
    }

    public record Item(int id, String name) {}
    public record SearchRequest(@Schema(requiredMode = Schema.RequiredMode.REQUIRED) String name) {}
}
