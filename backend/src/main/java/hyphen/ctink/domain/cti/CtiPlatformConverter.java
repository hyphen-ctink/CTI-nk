package hyphen.ctink.domain.cti;

import hyphen.ctink.domain.cti.enums.CtiPlatform;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

@Converter
public class CtiPlatformConverter implements AttributeConverter<Set<CtiPlatform>, String> {
    @Override
    public String convertToDatabaseColumn(Set<CtiPlatform> attribute) {
        if (attribute == null || attribute.isEmpty()) {
            return "";
        }

        return attribute.stream()
                .map(platform -> platform.name().toUpperCase())
                .collect(Collectors.joining(","));
    }

    @Override
    public Set<CtiPlatform> convertToEntityAttribute(String dbData) {
        if (dbData == null || dbData.isBlank()) {
            return Set.of();
        }

        return Arrays.stream(dbData.split(","))
                .map(value -> CtiPlatform.valueOf(value.toUpperCase()))
                .collect(Collectors.toSet());
    }
}
